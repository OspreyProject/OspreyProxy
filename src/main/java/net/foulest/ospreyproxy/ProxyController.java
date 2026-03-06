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

    // Rate limit configuration
    private static final int MAX_IP_REQUESTS = 20;
    private static final int MAX_GLOBAL_REQUESTS = 50000;
    private static final Duration RATE_DURATION = Duration.ofMinutes(1);

    // Rate limit buckets (per-IP)
    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .maximumSize(100_000)
            .build();

    // Global rate limiter to defend against distributed attacks
    // and prevent cache-eviction rate-limit reset attacks
    private static final Bucket GLOBAL_BUCKET = Bucket.builder()
            .addLimit(Bandwidth.builder()
                    .capacity(MAX_GLOBAL_REQUESTS)
                    .refillIntervally(MAX_GLOBAL_REQUESTS, Duration.ofMinutes(1))
                    .build())
            .build();

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

        // Global rate limit to defend against distributed attacks
        if (!GLOBAL_BUCKET.tryConsume(1)) {
            return errorResponse(429, "Rate limit exceeded");
        }

        // Per-IP rate limit
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
        if (!ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            return errorResponse(400, "URL scheme not allowed");
        }

        String host = parsedUri.getHost();

        // Blocks URLs without hosts
        if (host == null) {
            return errorResponse(400, "Malformed URL");
        }

        host = host.toLowerCase(Locale.ROOT);

        // Blocks URLs with userinfo (e.g., http://user:pass@host/) to prevent
        // URL parsing differentials between Java and upstream APIs
        if (parsedUri.getUserInfo() != null) {
            return errorResponse(400, "URL not allowed");
        }

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
                        .capacity(MAX_IP_REQUESTS)
                        .refillIntervally(MAX_IP_REQUESTS, RATE_DURATION)
                        .build())
                .build());
    }

    /**
     * Checks if an InetAddress is private or internal.
     * Used by the SSRF-safe DNS resolver at connection time.
     *
     * @param addr - The InetAddress to check.
     * @return true if the address is private/internal, false otherwise.
     */
    private static boolean isPrivateAddress(@NonNull InetAddress addr) {
        if (addr.isLoopbackAddress()
                || addr.isSiteLocalAddress()
                || addr.isLinkLocalAddress()
                || addr.isAnyLocalAddress()
                || addr.isMulticastAddress()) {
            return true;
        }

        // Block IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1, ::ffff:169.254.169.254)
        if (addr instanceof Inet6Address v6) {
            byte[] bytes = v6.getAddress();
            boolean isMapped = true;

            // Check for ::ffff:x.x.x.x (IPv4-mapped IPv6)
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isMapped = false;
                    break;
                }
            }

            // The next 2 bytes must be 0xFF for it to be an IPv4-mapped address
            if (isMapped && bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF) {
                byte[] v4Bytes = Arrays.copyOfRange(bytes, 12, 16);

                try {
                    InetAddress v4Addr = InetAddress.getByAddress(v4Bytes);
                    return isPrivateAddress(v4Addr);
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }

        // Block IPv6 unique-local addresses (fc00::/7, e.g., fd00:ec2::254 AWS metadata)
        if (addr instanceof Inet6Address) {
            int firstByte = addr.getAddress()[0] & 0xFF;

            if ((firstByte & 0xFE) == 0xFC) {
                return true;
            }
        }

        // Block IPv6 Teredo addresses (2001:0000::/32) which can encapsulate arbitrary
        // private IPv4 addresses that Java's standard checks won't flag
        if (addr instanceof Inet6Address) {
            byte[] bytes = addr.getAddress();

            if ((bytes[0] & 0xFF) == 0x20 && bytes[1] == 0x01
                    && bytes[2] == 0x00 && bytes[3] == 0x00) {
                return true;
            }
        }

        // Block IPv6 6to4 addresses (2002::/16) which embed IPv4 addresses in bytes 2-5
        // (e.g., 2002:a9fe:a9fe:: encapsulates 169.254.169.254)
        if (addr instanceof Inet6Address) {
            byte[] bytes = addr.getAddress();

            if ((bytes[0] & 0xFF) == 0x20 && (bytes[1] & 0xFF) == 0x02) {
                byte[] embeddedV4 = Arrays.copyOfRange(bytes, 2, 6);

                try {
                    InetAddress v4Addr = InetAddress.getByAddress(embeddedV4);

                    if (isPrivateAddress(v4Addr)) {
                        return true;
                    }
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }

        // Block carrier-grade NAT range (100.64.0.0/10)
        if (addr instanceof Inet4Address) {
            byte[] bytes = addr.getAddress();
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            return first == 100 && (second >= 64 && second <= 127);
        }
        return false;
    }

    /**
     * Checks if the host is private or internal to prevent SSRF attacks.
     * Only performs string-based hostname checks here; IP-level blocking
     * is handled by SSRF_SAFE_DNS_RESOLVER at connection time to avoid
     * DNS rebinding (TOCTOU) vulnerabilities from double-resolution.
     *
     * @param host - The hostname to check.
     * @return true if the host is considered private/internal, false otherwise.
     */
    private static boolean isPrivateHost(@NonNull String host) {
        // Block known internal hostnames by name
        if (host.equals("localhost")
                || host.endsWith(".local")
                || host.endsWith(".internal")
                || host.endsWith(".localhost")) {
            return true;
        }

        // Block raw IP addresses used directly as hostnames.
        // Uses numeric format detection to avoid DNS resolution (which would
        // reintroduce the TOCTOU window this method is designed to avoid).
        // IPv4 literals (e.g., "192.168.1.1") and IPv6 literals (e.g., "::1")
        // are detected by format and then checked against private ranges.
        if (isIpLiteral(host)) {
            try {
                InetAddress addr = InetAddress.getByName(host);
                return isPrivateAddress(addr);
            } catch (UnknownHostException e) {
                // Malformed IP literal; block it to be safe
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given host string is an IP address literal (IPv4 or IPv6)
     * without performing any DNS resolution.
     *
     * @param host - The hostname to check.
     * @return true if the host looks like an IP literal, false if it's a domain name.
     */
    @SuppressWarnings("CharacterComparison")
    private static boolean isIpLiteral(@NonNull String host) {
        // IPv6 literals from URI.getHost() come without brackets (e.g., "::1")
        if (host.contains(":")) {
            return true;
        }

        // IPv4: all characters must be digits or dots, and must contain at least one dot
        if (host.contains(".")) {
            for (int i = 0; i < host.length(); i++) {
                char c = host.charAt(i);

                if (c != '.' && (c < '0' || c > '9')) {
                    return false;
                }
            }
            return true;
        }
        return false;
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
