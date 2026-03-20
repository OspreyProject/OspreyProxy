/*
 * OspreyProxy - backend code for our proxy server using Spring MVC.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package net.foulest.ospreyproxy;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.AlphaMountainProvider;
import net.foulest.ospreyproxy.providers.PhishingBoxProvider;
import net.foulest.ospreyproxy.providers.PrecisionSecProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.util.*;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * REST controller for all proxy endpoints.
 */
@Slf4j
@RestController
public class ProxyHandler {

    // Maximum nesting depth enforced during upstream response validation
    private static final int MAX_NESTING_DEPTH = 50;

    // Jackson mapper for parsing request bodies and validating upstream responses
    private static final ObjectMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNumberLength(1000)
                            .maxNestingDepth(MAX_NESTING_DEPTH)
                            .maxStringLength(500_000)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .build())
            .build();

    // Pre-resolved JavaType for request body deserialization
    private static final JavaType MAP_TYPE = MAPPER.constructType(
            new TypeReference<Map<String, String>>() {
            }
    );

    // Connection manager
    private static final HttpClientConnectionManager CONNECTION_MANAGER = PoolingHttpClientConnectionManagerBuilder.create()
            .setDnsResolver(IPUtil.DNS_RESOLVER)
            .setMaxConnTotal(200)
            .setMaxConnPerRoute(200)
            .setDefaultConnectionConfig(ConnectionConfig.custom()
                    .setConnectTimeout(Timeout.ofSeconds(5))
                    .build())
            .build();

    // Custom request config
    private static final RequestConfig REQUEST_CONFIG = RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofSeconds(5))
            .setResponseTimeout(Timeout.ofSeconds(7))
            .setRedirectsEnabled(false)
            .build();

    // Custom HTTP client
    private static final CloseableHttpClient HTTP_CLIENT = HttpClients.custom()
            .setConnectionManager(CONNECTION_MANAGER)
            .setDefaultRequestConfig(REQUEST_CONFIG)
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .build();

    // Injected provider instances
    private final AlphaMountainProvider alphaMountainProvider;
    private final PrecisionSecProvider precisionSecProvider;
    private final PhishingBoxProvider phishingBoxProvider;

    // Injected LocalListUtil (static so it is accessible from static proxy methods)
    private static LocalListUtil localListUtil;

    /**
     * Constructor for ProxyHandler. Spring will automatically inject the provider instances.
     *
     * @param alphaMountainProvider alphaMountain's provider object.
     * @param precisionSecProvider PrecisionSec's provider object.
     * @param phishingBoxProvider PhishingBox's provider object.
     */
    public ProxyHandler(@NonNull AlphaMountainProvider alphaMountainProvider,
                        @NonNull PrecisionSecProvider precisionSecProvider,
                        @NonNull PhishingBoxProvider phishingBoxProvider,
                        @NonNull LocalListUtil localListUtil) {
        this.alphaMountainProvider = alphaMountainProvider;
        this.precisionSecProvider = precisionSecProvider;
        this.phishingBoxProvider = phishingBoxProvider;
        ProxyHandler.localListUtil = localListUtil;

        // Pre-warm Jackson type metadata
        MAPPER.constructType(Map.class);
        MAPPER.constructType(String.class);
        MAPPER.constructType(Object.class);
    }

    // -------------------------------------------------------------------------
    // Endpoints
    // -------------------------------------------------------------------------

    /**
     * Handles POST requests to the /alphamountain endpoint.
     * Keep @RequestBody(required = false) for rate-limiting.
     */
    @PostMapping(value = "/alphamountain",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleAlphaMountain(@RequestBody(required = false) byte[] body,
                                                      @NonNull HttpServletRequest request) {
        return proxyRequest(body, request, alphaMountainProvider);
    }

    /**
     * Handles POST requests to the /precisionsec endpoint.
     * Keep @RequestBody(required = false) for rate-limiting.
     */
    @PostMapping(value = "/precisionsec",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handlePrecisionSec(@RequestBody(required = false) byte[] body,
                                                     @NonNull HttpServletRequest request) {
        return proxyRequest(body, request, precisionSecProvider);
    }

    /**
     * Handles POST requests to the /phishingbox endpoint.
     * Keep @RequestBody(required = false) for rate-limiting.
     */
    @PostMapping(value = "/phishingbox",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handlePhishingBox(@RequestBody(required = false) byte[] body,
                                                    @NonNull HttpServletRequest request) {
        return proxyRequest(body, request, phishingBoxProvider);
    }

    // -------------------------------------------------------------------------
    // Core proxy logic
    // -------------------------------------------------------------------------

    /**
     * Core method implementing all proxy logic: IP extraction, rate limiting,
     * body parsing and validation, URL normalization and SSRF checks, and
     * upstream request execution.
     * <p>
     * Runs sequentially on a virtual thread. All blocking calls (body read,
     * upstream HTTP) park the virtual thread rather than blocking a platform thread.
     *
     * @param bodyBytes Raw request body bytes delivered by Spring MVC.
     * @param request The incoming servlet request (used for IP extraction).
     * @param provider The upstream provider to forward to.
     * @return A {@link ResponseEntity} to return to the client.
     */
    public static ResponseEntity<String> proxyRequest(byte[] bodyBytes,
                                                      @NonNull HttpServletRequest request,
                                                      @NonNull Provider provider) {
        String providerName = provider.getName();
        String hashedIp;

        // Validates and rate-limits the IP
        try {
            hashedIp = validateIP(request, provider, providerName);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        // Checks if the provider is enabled
        if (!provider.isEnabled()) {
            return ErrorUtil.RESP_503;
        }

        Map<String, String> incoming;

        // Validates the request's body
        try {
            incoming = validateBody(bodyBytes, provider, providerName, hashedIp);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        // Validates the API-Key header for PhishingBox requests
        if (provider instanceof PhishingBoxProvider) {
            try {
                validateApiKeyHeader(request, provider, providerName, hashedIp);
            } catch (StatusCodeException e) {
                return e.getStatus();
            }
        }

        @SuppressWarnings("NestedMethodCall")
        String url = Objects.toString(incoming.get("url"), "").trim();
        URI parsedUri;

        // Validates the request's URI
        try {
            parsedUri = validateURI(url, provider, providerName, hashedIp);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        String scheme;

        // Validates the domain's scheme
        try {
            scheme = validateScheme(parsedUri, provider, providerName, hashedIp);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        String host;

        // Validates the domain's host
        try {
            host = validateHost(parsedUri, provider, providerName, hashedIp);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        // Reconstructs the domain's URI
        try {
            parsedUri = reconstructURI(parsedUri, host, scheme, provider, providerName, hashedIp);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        // Validates the domain's DNS
        try {
            validateDNS(parsedUri, host, provider, providerName, hashedIp);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }

        // PrecisionSec only wants the bare domain, no scheme/path/query/fragment
        // Example: https://example.com/some/path?q=1 -> example.com
        if (provider instanceof PrecisionSecProvider) {
            try {
                parsedUri = new URI(host);
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                log.error("[{}] Unexpected PrecisionSec URI reconstruction failure for '{}': {} ({})",
                        providerName, parsedUri, e.getMessage(), e.getClass().getName());
                return ErrorUtil.RESP_502;
            }
        }

        // Records the request for our stats
        StatsUtil.recordRequest(providerName);

        // Skips upstream call and returns fake response for stress tests
        if (StressTestUtil.isEnabled()) {
            return ErrorUtil.RESP_200;
        }

        // Sends the normalized URL string to the upstream provider
        String normalizedUrl = parsedUri.toString();
        if (provider instanceof PhishingBoxProvider) {
            return executePhishingBox(host, providerName);
        } else {
            return executeUpstream(provider, providerName, normalizedUrl);
        }
    }

    /**
     * Executes the PhishingBox aggregate check synchronously.
     * <p>
     * Fans out to all seven sources in parallel on virtual threads, waits up to
     * 5 seconds for every source to respond, then assembles and returns a flat
     * JSON boolean map. Sources that time out or fail individually contribute
     * {@code false} to their respective keys (fail-open).
     * <p>
     * The returned JSON map has the following keys:
     * <pre>
     * {
     *   "adGuard":          true|false,
     *   "cleanBrowsing":    true|false,
     *   "cloudflare":       true|false,
     *   "phishDestroy":     true|false,
     *   "phishingDatabase": true|false,
     *   "quad9":            true|false,
     *   "switchCh":         true|false
     * }
     * </pre>
     *
     * @param host The validated, normalized host to check.
     * @param providerName  The display name of the provider.
     * @return A {@link ResponseEntity} containing the JSON map, or a 502 on serialization failure.
     */
    private static ResponseEntity<String> executePhishingBox(@NonNull String host,
                                                             @NonNull String providerName) {
        // Fans out all seven checks as CompletableFutures
        CompletableFuture<Boolean> adGuardFuture = CompletableFuture.supplyAsync(() -> FilteringDoHUtil.checkWithAdGuard(host));
        CompletableFuture<Boolean> cleanBrowsingFuture = CompletableFuture.supplyAsync(() -> FilteringDoHUtil.checkWithCleanBrowsing(host));
        CompletableFuture<Boolean> cloudflareFuture = CompletableFuture.supplyAsync(() -> FilteringDoHUtil.checkWithCloudflare(host));
        CompletableFuture<Boolean> phishDestroyFuture = CompletableFuture.supplyAsync(() -> localListUtil.isListed(LocalListUtil.Descriptor.PHISH_DESTROY, host));
        CompletableFuture<Boolean> phishingDatabaseFuture = CompletableFuture.supplyAsync(() -> localListUtil.isListed(LocalListUtil.Descriptor.PHISHING_DATABASE, host));
        CompletableFuture<Boolean> quad9Future = CompletableFuture.supplyAsync(() -> FilteringDoHUtil.checkWithQuad9(host));
        CompletableFuture<Boolean> switchChFuture = CompletableFuture.supplyAsync(() -> FilteringDoHUtil.checkWithSwitchCH(host));

        // Waits for all futures to complete
        try {
            CompletableFuture.allOf(
                    adGuardFuture,
                    cleanBrowsingFuture,
                    cloudflareFuture,
                    phishDestroyFuture,
                    phishingDatabaseFuture,
                    quad9Future,
                    switchChFuture
            ).orTimeout(5, TimeUnit.SECONDS).join();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
        }

        // Puts all the results in our JSON map
        Map<String, Boolean> resultMap = new LinkedHashMap<>();
        resultMap.put("adGuard", safeGet(adGuardFuture, providerName, "adGuard"));
        resultMap.put("cleanBrowsing", safeGet(cleanBrowsingFuture, providerName, "cleanBrowsing"));
        resultMap.put("cloudflare", safeGet(cloudflareFuture, providerName, "cloudflare"));
        resultMap.put("phishDestroy", safeGet(phishDestroyFuture, providerName, "phishDestroy"));
        resultMap.put("phishingDatabase", safeGet(phishingDatabaseFuture, providerName, "phishingDatabase"));
        resultMap.put("quad9", safeGet(quad9Future, providerName, "quad9"));
        resultMap.put("switchCh", safeGet(switchChFuture, providerName, "switchCh"));

        // Serializes the result map to JSON
        String responseBody;
        try {
            responseBody = MAPPER.writeValueAsString(resultMap);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize result map for '{}': {} ({})",
                    providerName, host, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }

        // Sends the serialized map back to the client
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(responseBody);
    }

    /**
     * Executes the upstream request to the provider synchronously.
     * <p>
     * Runs on a virtual thread: the blocking {@code HTTP_CLIENT.execute()} call parks
     * the virtual thread during I/O without blocking any platform thread.
     *
     * @param provider The provider configuration.
     * @param normalizedUrl The validated, normalized URL to check.
     * @return A {@link ResponseEntity} containing either the upstream response body
     *         or an appropriate error body.
     */
    private static ResponseEntity<String> executeUpstream(@NonNull Provider provider,
                                                          @NonNull String providerName,
                                                          @NonNull String normalizedUrl) {
        String method = provider.getMethod();
        ClassicRequestBuilder requestBuilder;
        String requestUrl = provider.buildRequestUrl(normalizedUrl);

        // Builds the request based on the provider's specified method (GET or POST).
        if (method.equals("GET")) {
            requestBuilder = ClassicRequestBuilder.get(requestUrl);
        } else {
            Map<String, Object> requestBody = provider.buildBody(normalizedUrl);
            String jsonBody = "";

            // buildBody() returns null for GET providers (e.g. PrecisionSec);
            // POST providers (e.g. AlphaMountain) return a populated map.
            if (requestBody != null) {
                try {
                    jsonBody = MAPPER.writeValueAsString(requestBody);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.error("[{}] Failed to serialize request body for '{}': {} ({})",
                            providerName, normalizedUrl, e.getMessage(), e.getClass().getName());
                    return ErrorUtil.RESP_502;
                }
            }

            requestBuilder = ClassicRequestBuilder.post(requestUrl).setEntity(jsonBody, ContentType.APPLICATION_JSON);
        }

        // Applies provider-specific headers (e.g., API key headers)
        for (Map.Entry<String, String> header : provider.getHeaders().entrySet()) {
            String key = header.getKey();
            String value = header.getValue();
            requestBuilder.addHeader(key, value);
        }

        try {
            // Executes the request and processes the response
            ClassicHttpRequest request = requestBuilder.build();
            return HTTP_CLIENT.execute(request, (ClassicHttpResponse response) -> {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                byte[] responseBytes = EntityUtils.toByteArray(entity);

                // Rejects non-200 responses with provider-specific logging and error mapping
                if (statusCode != 200) {
                    if (statusCode == 400) {
                        log.warn("[{}] Upstream request failed with status code: 400 ({})", providerName, normalizedUrl);
                    } else {
                        log.warn("[{}] Upstream request failed with status code: {}", providerName, statusCode);
                    }

                    CircuitBreakerUtil.recordFailure(providerName);

                    return switch (statusCode) {
                        case 400 -> ErrorUtil.RESP_400;
                        case 401 -> ErrorUtil.RESP_401;
                        case 404 -> ErrorUtil.RESP_404;
                        case 415 -> ErrorUtil.RESP_415;
                        case 429 -> ErrorUtil.RESP_429;
                        case 498 -> ErrorUtil.RESP_498;
                        default -> ErrorUtil.RESP_502;
                    };
                }

                // Rejects empty responses
                if (responseBytes == null || responseBytes.length == 0) {
                    log.error("[{}] Upstream response was empty", providerName);
                    return ErrorUtil.RESP_502;
                }

                // Rejects responses that exceed the maximum allowed size (10 KB)
                if (responseBytes.length > 10_000) {
                    log.error("[{}] Upstream response exceeded maximum size: {} bytes", providerName, responseBytes.length);
                    return ErrorUtil.RESP_502;
                }

                // Validate that the response is well-formed JSON using a streaming parser
                try (JsonParser parser = MAPPER.createParser(responseBytes)) {
                    int depth = 0;
                    JsonToken token;

                    while ((token = parser.nextToken()) != null) {
                        if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                            depth++;

                            // Rejects responses that exceed the maximum nesting depth
                            if (depth > MAX_NESTING_DEPTH) {
                                log.error("[{}] Upstream response exceeded maximum nesting depth: {}", providerName, depth);
                                return ErrorUtil.RESP_502;
                            }
                        } else if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                            depth--;
                        }
                    }
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.error("[{}] Failed to parse upstream response as JSON: {} ({})",
                            providerName, e.getMessage(), e.getClass().getName());
                    return ErrorUtil.RESP_502;
                }

                // Pass through the validated raw bytes as a UTF-8 string
                String responseBody = new String(responseBytes, StandardCharsets.UTF_8);

                // Record success now that the response is fully validated
                CircuitBreakerUtil.recordSuccess(providerName);

                // Return the response body to the client
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(responseBody);
            });
        } catch (SocketTimeoutException | ConnectionRequestTimeoutException | NoHttpResponseException e) {
            log.error("[{}] Upstream request timed out: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            CircuitBreakerUtil.recordFailure(providerName);
            return ErrorUtil.RESP_504;
        } catch (UnknownHostException e) {
            log.error("[{}] Upstream request blocked by SSRF resolver: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected error during upstream request: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            CircuitBreakerUtil.recordFailure(providerName);
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Validates and rate-limits a request's IP address, and returns a hashed IP.
     *
     * @param request The request to validate.
     * @param provider The provider to check rate limits against.
     * @param providerName The name of the provider.
     * @return A hashed representation of the client's IP address for rate limiting purposes.
     * @throws StatusCodeException If the IP address is found to be invalid/blocked.
     */
    private static String validateIP(@NonNull HttpServletRequest request, Provider provider, String providerName) {
        // Resolves client IP from X-Real-IP header (set by Nginx)
        // NOTE: Ensure your VPS is behind Cloudflare + Nginx with a firewall
        // that blocks direct connections. Otherwise, IP spoofing bypasses rate limits
        String realIp = request.getHeader("X-Real-IP");

        // Fallback to remote address if X-Real-IP is missing or empty
        if (realIp == null || realIp.isBlank()) {
            String remoteAddr = request.getRemoteAddr();
            realIp = (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr : "unknown";
        }

        // Logs a warning if we couldn't determine the client's IP address
        if (realIp.equals("unknown")) {
            log.warn("[{}] Could not determine client IP; applying rate limits to 'unknown' IP", providerName);
        }

        // Hashes the IP for rate limiting, or uses a synthetic IP in stress test mode
        String hashedIp = StressTestUtil.isEnabled()
                ? StressTestUtil.newSyntheticIp()
                : HashUtil.hashIp(realIp);

        // Invalid-request block check (no token consumed here)
        if (provider.isInvalidRequestBlocked(hashedIp)) {
            String violatorId = provider.getViolatorId(hashedIp);
            log.warn("[{}] 'Invalid request' rate limit active for {}", providerName, violatorId);
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // Burst rate limit check (consumes one token)
        if (RateLimitUtil.isBurstBlocked(provider, hashedIp, providerName)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // Sustained rate limit check (consumes one token)
        if (RateLimitUtil.isSustainedBlocked(provider, hashedIp, providerName)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // Short-circuit immediately if the provider's circuit breaker is open
        if (CircuitBreakerUtil.isOpen(providerName)) {
            log.warn("[{}] Circuit breaker OPEN; rejecting request without upstream call", providerName);
            throw new StatusCodeException(ErrorUtil.RESP_503);
        }
        return hashedIp;
    }

    /**
     * Validates the {@code API-Key} request header for PhishingBox requests.
     * The key must be present and must exactly match the value of the
     * {@code PHISHINGBOX_API_KEY} environment variable.
     *
     * @param request The incoming servlet request.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @throws StatusCodeException If the header is missing or does not match.
     */
    private static void validateApiKeyHeader(@NonNull HttpServletRequest request, Provider provider,
                                             String providerName, String hashedIp) {
        String providedKey = request.getHeader("API-Key");
        String expectedKey = PhishingBoxProvider.getApiKey();

        if (providedKey == null || providedKey.isBlank()) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked PhishingBox request with missing API-Key header");
            throw new StatusCodeException(ErrorUtil.RESP_401);
        }

        if (!providedKey.equals(expectedKey)) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked PhishingBox request with invalid API-Key header");
            throw new StatusCodeException(ErrorUtil.RESP_401);
        }
    }

    /**
     * Validates a request's body.
     *
     * @param bodyBytes The raw request body bytes to validate.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @return A map containing the parsed body fields if valid.
     * @throws StatusCodeException If the body is found to be invalid.
     */
    private static @NonNull Map<String, String> validateBody(byte[] bodyBytes, Provider provider, String providerName, String hashedIp) {
        byte[] bytes = (bodyBytes != null) ? bodyBytes : new byte[0];

        // Rejects empty bodies
        if (bytes.length == 0) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with empty body");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        Map<String, String> incoming;

        // Parses the request body as JSON
        try {
            incoming = MAPPER.readValue(bytes, MAP_TYPE);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with malformed JSON body: " + e.getMessage() + " (" + e.getClass().getName() + ")");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Rejects a null parse result (e.g., body was the JSON literal "null")
        if (incoming == null) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with null JSON body");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Rejects unexpected fields
        if (incoming.size() > 1) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with unexpected fields");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Rejects non-string url values
        try (JsonParser validator = MAPPER.createParser(bytes)) {
            JsonToken token;
            boolean inUrlValue = false;

            while ((token = validator.nextToken()) != null) {
                if (token == JsonToken.PROPERTY_NAME && "url".equals(validator.getString())) {
                    inUrlValue = true;
                } else if (inUrlValue) {
                    if (token != JsonToken.VALUE_STRING && token != JsonToken.VALUE_NULL) {
                        RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                                "Blocked request with non-string url value: " + token + " (" + token.asString() + ")");
                        throw new StatusCodeException(ErrorUtil.RESP_400);
                    }
                    break;
                }
            }
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected malformed JSON body on request: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }
        return incoming;
    }

    /**
     * Validates a request's URI.
     *
     * @param url The raw URL string to validate.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @return A normalized URI object if the URL is valid.
     * @throws StatusCodeException If the URL is found to be invalid.
     */
    private static URI validateURI(@NonNull String url, Provider provider, String providerName, String hashedIp) {
        // Rejects missing or empty URLs
        if (url.isBlank()) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with missing or empty URL");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Rejects excessively long URLs
        int length = url.length();
        if (length > 8192) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with excessively long URL (" + length + " characters)");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Normalizes and validates URL syntax
        URI parsedUri;
        try {
            String encoded = IPUtil.encodeIllegalUriChars(url);
            parsedUri = new URI(encoded).normalize();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with malformed URL: " + e.getMessage() + " (" + e.getClass().getName() + ")");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Prepends https:// for schemeless URLs (e.g., example.com)
        // new URI("example.com") parses the input as a path, not a host,
        // so we must fix this before validateHost runs.
        if (parsedUri.getScheme() == null) {
            try {
                parsedUri = new URI("https://" + parsedUri).normalize();
                parsedUri.toURL();
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with malformed URL: " + e.getMessage() + " (" + e.getClass().getName() + ")");
                throw new StatusCodeException(ErrorUtil.RESP_400);
            }
        }

        return parsedUri;
    }

    /**
     * Validates a request's scheme.
     *
     * @param parsedUri The parsed URI object to take the scheme from.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @return The normalized scheme string if valid (e.g., "http" or "https").
     * @throws StatusCodeException If the scheme is found to be invalid.
     */
    private static @NonNull String validateScheme(@NonNull URI parsedUri, Provider provider, String providerName, String hashedIp) {
        // By the time this is called, validateURI has already prepended https://
        // for schemeless inputs, so getScheme() is always non-null here.
        String scheme = parsedUri.getScheme().toLowerCase(Locale.ROOT);

        // Rejects unsupported schemes (only http and https allowed)
        if (!scheme.equals("http") && !scheme.equals("https")) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with disallowed URL scheme '" + scheme + "': " + parsedUri);
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }
        return scheme;
    }

    /**
     * Validates a request's host.
     *
     * @param parsedUri The parsed URI object to take the host from.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @return The normalized host string if valid.
     * @throws StatusCodeException If the host is found to be invalid.
     */
    private static @NonNull String validateHost(@NonNull URI parsedUri, Provider provider, String providerName, String hashedIp) {
        String host = parsedUri.getHost();

        // Extracts host from authority if getHost() is null
        if (host == null || host.isBlank()) {
            String authority = parsedUri.getRawAuthority();

            // Rejects requests with no authority/host component
            if (authority == null || authority.isBlank()) {
                RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with no host: " + parsedUri);
                throw new StatusCodeException(ErrorUtil.RESP_400);
            }

            // Handles bracketed IPv6 literals (e.g., [::1] or [::1]:8080)
            if (authority.charAt(0) == '[' && authority.contains("]")) {
                int endIndex = authority.indexOf(']');
                host = authority.substring(1, endIndex);
            } else {
                int lastColon = authority.lastIndexOf(':');
                host = lastColon >= 0 ? authority.substring(0, lastColon) : authority;
            }
        }

        host = host.toLowerCase(Locale.ROOT);

        // Removes leading dot(s)
        while (!host.isBlank() && host.charAt(0) == '.') {
            host = host.substring(1);
        }

        // Removes trailing dot(s)
        while (!host.isBlank() && host.charAt(host.length() - 1) == '.') {
            host = host.substring(0, host.length() - 1);
        }

        // Rejects hosts that are empty after normalization
        if (host.isBlank()) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with empty host: " + parsedUri);
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Rejects hosts without a . symbol
        if (!host.contains(".")) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with host missing dot: " + parsedUri);
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }
        return host;
    }

    /**
     * Validates a request's DNS.
     *
     * @param parsedUri The parsed URI object to take the host from for DNS validation.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @throws StatusCodeException If the DNS is found to be invalid.
     */
    private static void validateDNS(@NonNull URI parsedUri, @NonNull String host, Provider provider, String providerName, String hashedIp) {
        // Blocks private/internal hosts (string-based checks; IP-level blocking happens
        // inside IPUtil's DNS resolver at connection time to prevent DNS rebinding)
        if (IPUtil.isPrivateHost(host)) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request to private/internal host: " + parsedUri);
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        boolean isIpLiteral = host.contains(":") || host.chars().allMatch(c -> c == '.' || (c >= '0' && c <= '9'));

        // Rejects hostnames that don't exist in DNS (doesn't log)
        if (!isIpLiteral && !DoHUtil.hostExists(host)) {
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }
    }

    /**
     * Reconstructs a URI with the normalized host and scheme.
     *
     * @param parsedUri The parsed URI object to reconstruct.
     * @param host The normalized host.
     * @param scheme The normalized scheme.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender.
     * @return The reconstructed URI object.
     * @throws StatusCodeException If the port is found to be invalid.
     */
    private static URI reconstructURI(@NonNull URI parsedUri, @NonNull String host, @NonNull String scheme,
                                      Provider provider, String providerName, String hashedIp) {
        // Reconstructs the URI with the normalized host and scheme
        try {
            int port = parsedUri.getPort();

            // Rejects ports outside the valid range (1-65535); -1 means no port specified
            if (port != -1 && (port < 1 || port > 65535)) {
                RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with invalid port: " + port + " (" + parsedUri + ")");
                throw new StatusCodeException(ErrorUtil.RESP_400);
            }

            String authority = port == -1 ? host : (host + ":" + port);
            String rawPath = parsedUri.getRawPath();
            String rawQuery = parsedUri.getRawQuery();
            String schemeSpecific = "//" + authority + (rawPath != null ? rawPath : "") + (rawQuery != null ? "?" + rawQuery : "");
            parsedUri = new URI(scheme, schemeSpecific, null);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected URI reconstruction failure for '{}': {} ({})", providerName, parsedUri, e.getMessage(), e.getClass().getName());
            throw new StatusCodeException(ErrorUtil.RESP_502);
        }
        return parsedUri;
    }

    /**
     * Retrieves the result of a {@link CompletableFuture}, returning {@code false}
     * if the future completed exceptionally or was cancelled (e.g., due to timeout).
     *
     * @param future       The future to harvest.
     * @param providerName The provider name for logging context.
     * @param sourceName   The source name for logging context.
     * @return The future's boolean value, or {@code false} on failure.
     */
    private static boolean safeGet(@NonNull CompletableFuture<Boolean> future,
                                   @NonNull String providerName,
                                   @NonNull String sourceName) {
        try {
            return Boolean.TRUE.equals(future.getNow(false));
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Source '{}' did not complete in time or failed: {} ({})",
                    providerName, sourceName, e.getMessage(), e.getClass().getName()
            );
            return false;
        }
    }
}
