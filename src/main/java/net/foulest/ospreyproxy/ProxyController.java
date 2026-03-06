package net.foulest.ospreyproxy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.providers.AlphaMountainProvider;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@RestController
public class ProxyController {

    // Shared instances
    private static final ObjectMapper MAPPER = JsonMapper.builder().build();
    private static final RestClient REST_CLIENT = RestClient.builder()
            .requestFactory(new HttpComponentsClientHttpRequestFactory(
                    HttpClients.custom()
                            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                                    .setMaxConnTotal(50)
                                    .setMaxConnPerRoute(20)
                                    .setDefaultSocketConfig(SocketConfig.custom()
                                            .setSoTimeout(Timeout.ofSeconds(5))
                                            .build())
                                    .build())
                            .setDefaultRequestConfig(RequestConfig.custom()
                                    .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                                    .setResponseTimeout(Timeout.ofSeconds(5))
                                    .build())
                            .build()))
            .build();

    // IP salt for hashing to prevent rainbow table attacks
    private static final byte[] IP_SALT = generateSalt();

    // Rate limit buckets
    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .expireAfterAccess(1, TimeUnit.HOURS)
            .maximumSize(100_000)
            .build();

    // Rate limit configuration
    private static final int MAX_REQUESTS = 20;
    private static final Duration RATE_DURATION = Duration.ofMinutes(1);

    // Only allow these URI schemes
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    // -------------------------------------------------------------------------
    // Endpoints
    // -------------------------------------------------------------------------

    @PostMapping("/alphamountain")
    public ResponseEntity<String> checkWithAlphaMountain(@RequestBody Map<String, String> incoming,
                                                         HttpServletRequest request) {
        return proxyRequest(incoming, request,
                AlphaMountainProvider::buildBody,
                AlphaMountainProvider.getApiUrl());
    }

    // -------------------------------------------------------------------------
    // Core proxy logic
    // -------------------------------------------------------------------------

    /**
     * Validates the incoming request, builds the upstream body, proxies it,
     * and returns a sanitized response. All endpoints funnel through here.
     *
     * @param incoming    - The raw request body from the client.
     * @param request     - The HTTP request (used for IP-based rate limiting).
     * @param bodyBuilder - A function that maps a validated URL to the upstream request body.
     * @param apiUrl      - The upstream API URL to forward the request to.
     * @return A sanitized JSON response or an appropriate error.
     */
    private ResponseEntity<String> proxyRequest(@NonNull Map<String, String> incoming,
                                                @NonNull HttpServletRequest request,
                                                @NonNull BodyBuilder bodyBuilder,
                                                @NonNull String apiUrl) {
        // Blocks requests with unexpected fields to prevent abuse
        if (incoming.size() > 1) {
            return errorResponse(400, "Unexpected fields in request");
        }

        // Blocks requests with excessively large bodies
        if (request.getContentLengthLong() > 10_240) {
            return errorResponse(413, "Request body too large");
        }

        // noinspection NestedMethodCall
        String ip = hashIp(request.getRemoteAddr());

        // Rate limits by IP
        if (!getBucket(ip).tryConsume(1)) {
            return errorResponse(429, "Rate limit exceeded");
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
            parsedUri.toURL(); // Called for validation only
        } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
            return errorResponse(400, "Malformed URL");
        }

        String scheme = parsedUri.getScheme();

        // Blocks URLs without allowed schemes
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            return errorResponse(400, "URL scheme not allowed");
        }

        String host = parsedUri.getHost();

        // Blocks URLs without hosts
        if (host == null) {
            return errorResponse(400, "Malformed URL");
        }

        host = host.toLowerCase(Locale.ROOT);

        // Blocks private or internal hosts
        if (isPrivateHost(host)) {
            return errorResponse(400, "URL not allowed");
        }

        Map<String, Object> apiBody;

        // Builds the upstream request body
        try {
            apiBody = bodyBuilder.build(url);
        } catch (RuntimeException e) {
            return errorResponse(500, "Failed to build request");
        }

        String rawResponse;

        // Proxies the request to the upstream API
        try {
            rawResponse = REST_CLIENT.post()
                    .uri(apiUrl)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(apiBody)
                    .retrieve()
                    .body(String.class);
        } catch (RestClientException e) {
            return errorResponse(502, "Upstream request failed");
        }

        // Blocks excessively large responses to prevent abuse
        if (rawResponse != null && rawResponse.length() > 100_000) {
            return errorResponse(502, "Upstream response too large");
        }

        // Parses and re-serializes the response to strip any unexpected content
        try {
            JsonNode json = MAPPER.readTree(rawResponse);
            String body = MAPPER.writeValueAsString(json);
            return ResponseEntity.ok(body);
        } catch (JacksonException e) {
            return errorResponse(502, "Invalid JSON in upstream response");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Functional interface for building the upstream request body from a validated URL.
     */
    @FunctionalInterface
    interface BodyBuilder {

        Map<String, Object> build(String url);
    }

    /**
     * Gets or creates a rate limiting bucket for the given IP address.
     *
     * @param ip - The IP address to get the bucket for.
     * @return The rate limiting bucket associated with the IP.
     */
    private Bucket getBucket(@NonNull String ip) {
        return buckets.get(ip, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(MAX_REQUESTS)
                        .refillIntervally(MAX_REQUESTS, RATE_DURATION)
                        .build())
                .build());
    }

    /**
     * Checks if the host is private or internal to prevent SSRF attacks.
     *
     * @param host - The hostname to check.
     * @return true if the host is considered private/internal, false otherwise.
     */
    private static boolean isPrivateHost(@NonNull String host) {
        // Block known internal hostnames by name
        if (host.equals("localhost")
                || host.endsWith(".local")
                || host.endsWith(".internal")) {
            return true;
        }

        // Block AWS/GCP/Azure metadata endpoints by name
        if (host.equals("169.254.169.254")
                || host.equals("metadata.google.internal")) {
            return true;
        }

        // Let InetAddress handle all IP range checks (IPv4 + IPv6)
        try {
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (addr.isLoopbackAddress()
                        || addr.isSiteLocalAddress()
                        || addr.isLinkLocalAddress()
                        || addr.isAnyLocalAddress()
                        || addr.isMulticastAddress()) {
                    return true;
                }
            }
            return false;
        } catch (UnknownHostException e) {
            return true;
        }
    }

    /**
     * Generates a random salt for hashing IP addresses to prevent rainbow table attacks.
     *
     * @return A random byte array to be used as a salt for hashing IP addresses.
     */
    private static byte @NonNull [] generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Hashes the IP address using SHA-256 with a salt to prevent rainbow table attacks.
     *
     * @param ip - The IP address to hash.
     * @return A hexadecimal string representation of the hashed IP address.
     */
    private static String hashIp(@NonNull String ip) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(IP_SALT);

            byte[] bytes = ip.getBytes(StandardCharsets.UTF_8);
            byte[] hash = digest.digest(bytes);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Helper method to create a standardized error response with a JSON body.
     *
     * @param status - The HTTP status code to return.
     * @param message - The error message to include in the response body.
     * @return A ResponseEntity with the specified status and a JSON body containing the error message.
     */
    private static @NonNull ResponseEntity<String> errorResponse(int status, String message) {
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
