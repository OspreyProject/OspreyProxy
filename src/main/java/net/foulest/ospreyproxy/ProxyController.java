package net.foulest.ospreyproxy;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.providers.AlphaMountainProvider;
import net.foulest.ospreyproxy.providers.PrecisionSecProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.util.BucketUtil;
import net.foulest.ospreyproxy.util.HashUtil;
import net.foulest.ospreyproxy.util.IPUtil;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.util.Timeout;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@RestController
public class ProxyController {

    /**
     * Custom DNS resolver that validates resolved IPs against private ranges
     * at connection time to prevent DNS rebinding attacks (TOCTOU).
     */
    private static final DnsResolver SSRF_SAFE_DNS_RESOLVER = new DnsResolver() {
        private final SystemDefaultDnsResolver delegate = SystemDefaultDnsResolver.INSTANCE;

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            InetAddress[] addresses = delegate.resolve(host);

            for (InetAddress addr : addresses) {
                if (IPUtil.isPrivateAddress(addr)) {
                    throw new UnknownHostException("Blocked: resolved to private address");
                }
            }
            return addresses;
        }

        @Override
        public String resolveCanonicalHostname(String host) throws UnknownHostException {
            return delegate.resolveCanonicalHostname(host);
        }
    };

    // JSON mapper for parsing and re-serializing upstream responses
    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    // Only allow these URI schemes
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    // Custom RestClient with SSRF protections and timeouts
    private static final RestClient REST_CLIENT = RestClient.builder()
            .requestFactory(new HttpComponentsClientHttpRequestFactory(
                    HttpClients.custom()
                            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                                    .setMaxConnTotal(2000)
                                    .setMaxConnPerRoute(1000)
                                    .setDnsResolver(SSRF_SAFE_DNS_RESOLVER)
                                    .setDefaultSocketConfig(SocketConfig.custom()
                                            .setSoTimeout(Timeout.ofSeconds(5))
                                            .build())
                                    .build())
                            .setDefaultRequestConfig(RequestConfig.custom()
                                    .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                                    .setResponseTimeout(Timeout.ofSeconds(5))
                                    .build())
                            .disableRedirectHandling()
                            .build()))
            .build();

    // -------------------------------------------------------------------------
    // Endpoints
    // -------------------------------------------------------------------------

    @PostMapping("/alphamountain")
    public ResponseEntity<String> checkWithAlphaMountain(@RequestBody Map<String, String> incoming,
                                                         HttpServletRequest request,
                                                         AlphaMountainProvider provider) {
        return proxyRequest(incoming, request, provider);
    }

    @PostMapping("/precisionsec")
    public ResponseEntity<String> checkWithPrecisionSec(@RequestBody Map<String, String> incoming,
                                                        HttpServletRequest request,
                                                        PrecisionSecProvider provider) {
        return proxyRequest(incoming, request, provider);
    }

    /**
     * Catch-all handler for all unmapped paths and methods.
     * Returns a generic 404 JSON response to prevent Spring's default error
     * handler from leaking path info via Problem Details.
     */
    @RequestMapping("/**")
    public ResponseEntity<String> catchAll() {
        return errorResponse(404, "Not found");
    }

    // -------------------------------------------------------------------------
    // Core proxy logic
    // -------------------------------------------------------------------------

    /**
     * Validates the incoming request, builds the upstream request, proxies it,
     * and returns a sanitized response. All endpoints funnel through here.
     *
     * @param incoming - The raw request body from the client.
     * @param request  - The HTTP request (used for IP-based rate limiting).
     * @param provider - The upstream provider to forward the request to.
     * @return A sanitized JSON response or an appropriate error.
     */
    @SuppressWarnings("ResultOfMethodCallIgnored")
    private ResponseEntity<String> proxyRequest(@NotNull Map<String, String> incoming,
                                                @NotNull HttpServletRequest request,
                                                @NotNull Provider provider) {
        // Blocks requests with unexpected fields to prevent abuse
        if (incoming.size() > 1) {
            return errorResponse(400, "Unexpected fields in request");
        }

        // noinspection NestedMethodCall
        String hashedIp = HashUtil.hashIp(request.getRemoteAddr());

        // Global burst rate limit
        if (!BucketUtil.GLOBAL_BURST_BUCKET.tryConsume(1)) {
            return errorResponse(429, "Global burst rate limit exceeded");
        }

        // Global sustained rate limit
        if (!BucketUtil.GLOBAL_SUSTAINED_BUCKET.tryConsume(1)) {
            return errorResponse(429, "Global sustained rate limit exceeded");
        }

        // Per-IP burst rate limit
        if (!BucketUtil.getBurstBucket(hashedIp).tryConsume(1)) {
            return errorResponse(429, "Per-IP burst rate limit exceeded");
        }

        // Per-IP sustained rate limit
        if (!BucketUtil.getSustainedBucket(hashedIp).tryConsume(1)) {
            return errorResponse(429, "Per-IP sustained rate limit exceeded");
        }

        String url = incoming.getOrDefault("url", "").trim();

        // Blocks URLs that are empty
        if (url.isEmpty()) {
            return errorResponse(400, "Missing or empty 'url' field");
        }

        // Blocks URLs that are too long
        if (url.length() > 2048) {
            return errorResponse(400, "URL too long");
        }

        URI parsedUri;

        // Parses and validates the URL
        try {
            parsedUri = new URI(url).normalize();
        } catch (URISyntaxException | IllegalArgumentException e) {
            return errorResponse(400, "Malformed URL");
        }

        String scheme = parsedUri.getScheme();

        // Inserts 'https://' for schemeless URLs (e.g., example.com) to prevent them from being blocked
        if (scheme == null) {
            try {
                parsedUri = new URI("https://" + url).normalize();
                parsedUri.toURL(); // Called for validation only
                scheme = parsedUri.getScheme();
            } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
                return errorResponse(400, "Malformed URL");
            }
        }

        // Blocks URLs without allowed schemes
        // noinspection NestedMethodCall
        if (!ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            return errorResponse(400, "URL scheme not allowed");
        }

        String host = parsedUri.getHost();

        // URI.getHost() returns null for hostnames containing underscores
        // (technically invalid per RFC 2396 but common in real-world URLs)
        // Fall back to manual extraction so these reach upstream validation
        if (host == null) {
            String authority = parsedUri.getRawAuthority();

            if (authority == null) {
                return errorResponse(400, "Malformed URL");
            }

            // Strip port if present (e.g. "example.com:8080" -> "example.com")
            int endIndex = authority.lastIndexOf(':');
            host = authority.contains(":") ? authority.substring(0, endIndex) : authority;
        }

        // Blocks URLs with blank hosts
        if (host.isBlank()) {
            return errorResponse(400, "Malformed URL");
        }

        host = host.toLowerCase(Locale.ROOT);

        // Blocks URLs with userinfo (e.g., http://user:pass@host/) to prevent
        // URL parsing differentials between Java and upstream APIs
        if (parsedUri.getUserInfo() != null) {
            return errorResponse(400, "URL not allowed");
        }

        // Blocks private or internal hosts
        if (IPUtil.isPrivateHost(host)) {
            return errorResponse(400, "URL not allowed");
        }

        String normalizedUrl = parsedUri.toString();
        String rawResponse;

        // Maximum allowed upstream response size (100 KB)
        int maxResponseSize = 100_000;

        // Proxies the request to the upstream provider.
        // Uses exchange() with a byte-limited reader to abort early if the upstream
        // sends more data than expected, preventing large responses from consuming
        // unbounded heap memory.
        try {
            RestClient.RequestHeadersSpec<?> requestSpec;
            String method = provider.getMethod();
            String uri = provider.buildRequestUrl(normalizedUrl);

            if (method.equalsIgnoreCase("GET")) {
                requestSpec = REST_CLIENT.get().uri(uri);
            } else {
                RestClient.RequestBodySpec postSpec = REST_CLIENT.post().uri(uri);
                Map<String, Object> requestBody = provider.buildBody(normalizedUrl);

                if (requestBody != null) {
                    postSpec = postSpec.contentType(MediaType.APPLICATION_JSON).body(requestBody);
                }

                requestSpec = postSpec;
            }

            // Apply any provider-specific headers (e.g., API key headers)
            for (Map.Entry<String, String> header : provider.getHeaders().entrySet()) {
                String key = header.getKey();
                String value = header.getValue();
                requestSpec.header(key, value);
            }

            rawResponse = requestSpec.exchange((req, res) -> {
                HttpStatusCode statusCode = res.getStatusCode();

                if (statusCode.isError()) {
                    throw new RestClientException("Upstream returned " + statusCode);
                }

                try (var inputStream = res.getBody()) {
                    byte[] buffer = inputStream.readNBytes(maxResponseSize + 1);

                    if (buffer.length > maxResponseSize) {
                        return null; // Signal that the response was too large
                    }
                    return new String(buffer, StandardCharsets.UTF_8);
                }
            });
        } catch (RestClientException e) {
            return errorResponse(502, "Upstream request failed");
        }

        // Parses the upstream response to ensure it's valid JSON, then re-serializes
        try {
            JsonNode json = MAPPER.readTree(rawResponse);
            String jsonString = json.toString();
            return ResponseEntity.ok(jsonString);
        } catch (JacksonException e) {
            return errorResponse(502, "Invalid JSON in upstream response");
        }
    }

    // -------------------------------------------------------------------------
    // Helper methods
    // -------------------------------------------------------------------------

    /**
     * Helper method to create a standardized error response with a JSON body.
     *
     * @param status  - The HTTP status code to return.
     * @param message - The error message to include in the response body.
     * @return A ResponseEntity with the specified status and a JSON body containing the error message.
     */
    private static @NotNull ResponseEntity<String> errorResponse(int status, String message) {
        try {
            String body = MAPPER.writeValueAsString(Map.of("error", message));
            return ResponseEntity.status(status)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body);
        } catch (JacksonException e) {
            return ResponseEntity.status(status)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Internal server error\"}");
        }
    }
}
