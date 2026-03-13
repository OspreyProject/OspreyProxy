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
import net.foulest.ospreyproxy.providers.AlphaMountainProvider;
import net.foulest.ospreyproxy.providers.PrecisionSecProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.HashUtil;
import net.foulest.ospreyproxy.util.IPUtil;
import net.foulest.ospreyproxy.util.StressTestUtil;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ConnectionRequestTimeoutException;
import org.apache.hc.core5.http.ContentType;
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

import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * REST controller for all proxy endpoints.
 */
@Slf4j
@RestController
public class ProxyHandler {

    // Injected provider instances
    private final AlphaMountainProvider alphaMountainProvider;
    private final PrecisionSecProvider precisionSecProvider;

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

    // Only allow these URI schemes
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    // Maximum allowed upstream response size in bytes (100 KB)
    private static final int MAX_RESPONSE_SIZE = 100_000;

    // Request statistics per provider
    private static final class RequestStats {

        final AtomicLong totalRequestCount = new AtomicLong(0);
        final AtomicLong secondBucket = new AtomicLong(0);
        final AtomicLong minuteBucket = new AtomicLong(0);
        final AtomicLong peakReqPerSec = new AtomicLong(0);
        final AtomicLong highestReqPerMin = new AtomicLong(0);
        final AtomicLong highestPeakReqPerSec = new AtomicLong(0);

        // Greedy window simulation (scaled x100 to avoid floats in AtomicLong)
        final AtomicLong simulatedTokenPoolScaled = new AtomicLong(SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L);
        final AtomicLong highestMinWindowNeeded = new AtomicLong(0);
    }

    // The provider's greedy window capacity to simulate, in req/min
    private static final long SIMULATED_PROVIDER_WINDOW_PER_MIN = 1_740;

    private static final ConcurrentHashMap<String, RequestStats> PROVIDER_STATS = new ConcurrentHashMap<>();

    // Scheduler for periodic request statistics printing
    private static final ScheduledExecutorService REQUEST_STATS_SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "RequestStats");
        thread.setDaemon(true);
        return thread;
    });

    static {
        // Every second: drain secondBucket into minuteBucket, update peakReqPerSec, simulate greedy window
        REQUEST_STATS_SCHEDULER.scheduleAtFixedRate(() -> {
            for (Map.Entry<String, RequestStats> entry : PROVIDER_STATS.entrySet()) {
                String name = entry.getKey();
                RequestStats stats = entry.getValue();
                long reqThisSec = stats.secondBucket.getAndSet(0);
                stats.minuteBucket.addAndGet(reqThisSec);

                long current = stats.peakReqPerSec.get();
                if (reqThisSec > current) {
                    stats.peakReqPerSec.set(reqThisSec);
                }

                // Simulate the provider's greedy token pool:
                // refill rate = SIMULATED_PROVIDER_WINDOW_PER_MIN / 60.0 tokens/sec (scaled x100)
                long refillScaled = 2900;
                long consumeScaled = reqThisSec * 100L;
                long capScaled = SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L;

                // Apply refill then consume, clamping pool between 0 and cap
                long pool = stats.simulatedTokenPoolScaled.get();
                pool = Math.min(pool + refillScaled, capScaled);
                pool = Math.max(pool - consumeScaled, 0);
                stats.simulatedTokenPoolScaled.set(pool);

                // Net drift this second: negative means we're consuming faster than the window refills
                double netDriftPerSec = (refillScaled - consumeScaled) / 100.0;

                if (netDriftPerSec < 0) {
                    // Minimum window (req/min) needed so refill rate >= consume rate: ceil(reqThisSec * 60)
                    long minWindowNeeded = (long) Math.ceil(reqThisSec * 60.0);

                    if (minWindowNeeded > stats.highestMinWindowNeeded.get()) {
                        stats.highestMinWindowNeeded.set(minWindowNeeded);
                        log.warn("[{}] Greedy window deficit — Consume vs refill: {}/sec | Min window needed: {}/min",
                                name, String.format("%.2f", netDriftPerSec), minWindowNeeded);
                    }
                }
            }
        }, 1, 1, TimeUnit.SECONDS);

        // Every 60 seconds: check per-provider highs and log only when a new record is set
        REQUEST_STATS_SCHEDULER.scheduleAtFixedRate(() -> PROVIDER_STATS.forEach((name, stats) -> {
            long reqThisMin = stats.minuteBucket.getAndSet(0);
            long peakThisMin = stats.peakReqPerSec.getAndSet(0);

            if (reqThisMin > stats.highestReqPerMin.get()) {
                stats.highestReqPerMin.set(reqThisMin);
                log.warn("[{}] New highest req/min: {}", name, reqThisMin);
            }

            if (peakThisMin > stats.highestPeakReqPerSec.get()) {
                stats.highestPeakReqPerSec.set(peakThisMin);
                log.warn("[{}] New highest req/sec: {}", name, peakThisMin);
            }
        }), 60, 60, TimeUnit.SECONDS);
    }

    /**
     * Custom {@link DnsResolver} that validates every resolved IP against the private/internal
     * address blocklist in {@link IPUtil} before returning it to the connection manager.
     * <p>
     * Because resolution happens at connection time (not during URL parsing), this approach
     * is not vulnerable to DNS rebinding (TOCTOU): the address we check is exactly the address
     * that will be used for the connection.
     */
    private static final DnsResolver SSRF_SAFE_DNS_RESOLVER = new DnsResolver() {

        /**
         * Resolves {@code host} to a list of safe (non-private) addresses.
         * Called by the connection manager before opening a socket.
         */
        @Override
        public InetAddress @NonNull [] resolve(String host) throws UnknownHostException {
            InetAddress[] resolved = InetAddress.getAllByName(host);
            List<InetAddress> safe = new ArrayList<>(resolved.length);

            for (InetAddress addr : resolved) {
                if (IPUtil.isPrivateAddress(addr)) {
                    throw new UnknownHostException("Blocked: '" + host + "' resolved to private address");
                }

                safe.add(addr);
            }

            if (safe.isEmpty()) {
                throw new UnknownHostException("No safe addresses resolved for: " + host);
            }
            return safe.toArray(new InetAddress[0]);
        }

        /**
         * Returns the canonical (fully-qualified) hostname for the given host.
         * Delegates to the JVM's standard resolver; no SSRF risk here since
         * this performs a reverse lookup on a name, not a forward lookup that
         * could return a private address for outbound connections.
         */
        @Override
        public String resolveCanonicalHostname(String host) throws UnknownHostException {
            InetAddress addr = InetAddress.getByName(host);
            return addr.getCanonicalHostName();
        }
    };

    // Connection manager
    private static final HttpClientConnectionManager CONNECTION_MANAGER = PoolingHttpClientConnectionManagerBuilder.create()
            .setDnsResolver(SSRF_SAFE_DNS_RESOLVER)
            .setMaxConnTotal(200)
            .setMaxConnPerRoute(200)
            .setDefaultConnectionConfig(ConnectionConfig.custom()
                    .setConnectTimeout(Timeout.ofSeconds(5))
                    .build())
            .build();

    // Custom request config
    private static final RequestConfig REQUEST_CONFIG = RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofSeconds(5))
            .setResponseTimeout(Timeout.ofSeconds(5))
            .setRedirectsEnabled(false)
            .build();

    // Custom HTTP client
    private static final CloseableHttpClient HTTP_CLIENT = HttpClients.custom()
            .setConnectionManager(CONNECTION_MANAGER)
            .setDefaultRequestConfig(REQUEST_CONFIG)
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .build();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public ProxyHandler(AlphaMountainProvider alphaMountainProvider,
                        PrecisionSecProvider precisionSecProvider) {
        this.alphaMountainProvider = alphaMountainProvider;
        this.precisionSecProvider = precisionSecProvider;

        // Pre-warm Jackson type metadata
        MAPPER.constructType(Map.class);
        MAPPER.constructType(String.class);
        MAPPER.constructType(Object.class);
    }

    // -------------------------------------------------------------------------
    // Endpoints
    // -------------------------------------------------------------------------

    /**
     * Handles requests to alphaMountain's API.
     */
    @PostMapping(value = "/alphamountain",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleAlphaMountain(@RequestBody(required = false) byte[] body,
                                                      HttpServletRequest request) {
        return proxyRequest(body, request, alphaMountainProvider);
    }

    /**
     * Handles requests to PrecisionSec's API.
     */
    @PostMapping(value = "/precisionsec",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handlePrecisionSec(@RequestBody(required = false) byte[] body,
                                                     HttpServletRequest request) {
        return proxyRequest(body, request, precisionSecProvider);
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
    public ResponseEntity<String> proxyRequest(byte[] bodyBytes,
                                                @NonNull HttpServletRequest request,
                                                @NonNull Provider provider) {
        // ------------------------------------------------
        // IP Extraction and Rate Limiting
        // ------------------------------------------------

        // Resolve client IP from X-Real-IP header (set by Nginx).
        // NOTE: Ensure your VPS is behind Cloudflare + Nginx with a firewall
        // that blocks direct connections. Otherwise, IP spoofing bypasses rate limits.
        String realIp = request.getHeader("X-Real-IP");

        // Fallback to remote address if X-Real-IP is missing or empty
        if (realIp == null || realIp.isBlank()) {
            String remoteAddr = request.getRemoteAddr();
            realIp = (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr : "unknown";
        }

        String providerName = provider.getName();

        // Log a warning if we couldn't determine the client's IP address
        if (realIp.equals("unknown")) {
            log.warn("[{}] Could not determine client IP; applying rate limits to 'unknown' IP", providerName);
        }

        // Hash the IP for rate limiting, or use a synthetic IP in stress test mode
        String hashedIp = StressTestUtil.isEnabled()
                ? StressTestUtil.syntheticIp()
                : HashUtil.hashIp(realIp);

        // Burst rate limit check (consumes one token)
        if (isBurstBlocked(provider, hashedIp, providerName)) {
            return ErrorUtil.RESP_429;
        }

        // Sustained rate limit check (consumes one token)
        if (isSustainedBlocked(provider, hashedIp, providerName)) {
            return ErrorUtil.RESP_429;
        }

        // Invalid-request block check (no token consumed here)
        if (provider.isInvalidRequestBlocked(hashedIp)) {
            log.warn("[{}] RATE LIMIT ACTIVE: Invalid request | {}", providerName, provider.getViolatorId(hashedIp));
            return ErrorUtil.RESP_429;
        }

        // ------------------------------------------------
        // Request Body Parsing and Validation
        // ------------------------------------------------

        byte[] bytes = (bodyBytes != null) ? bodyBytes : new byte[0];

        // Rejects empty bodies
        if (bytes.length == 0) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with empty body", ErrorUtil.RESP_400);
        }

        Map<String, String> incoming;

        // Parse the request body as JSON
        try {
            incoming = MAPPER.readValue(bytes, MAP_TYPE);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with malformed JSON body (" + e.getClass().getName() + ")",
                    ErrorUtil.RESP_400);
        }

        // Rejects a null parse result (e.g., body was the JSON literal "null")
        if (incoming == null) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with null JSON body", ErrorUtil.RESP_400);
        }

        // Rejects unexpected fields
        if (incoming.size() > 1) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with unexpected fields", ErrorUtil.RESP_400);
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
                        return rejectInvalidRequest(provider, hashedIp, providerName,
                                "Blocked request with non-string url value", ErrorUtil.RESP_400);
                    }
                    break;
                }
            }
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with malformed JSON body (" + e.getClass().getName() + ")",
                    ErrorUtil.RESP_400);
        }

        // ------------------------------------------------
        // URL Normalization and Validation
        // ------------------------------------------------

        String rawUrl = incoming.getOrDefault("url", "");
        String url = rawUrl != null ? rawUrl.trim() : "";

        // Rejects missing or empty URLs
        if (url.isEmpty()) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with missing or empty URL", ErrorUtil.RESP_400);
        }

        // Rejects excessively long URLs
        if (url.length() > 8192) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with excessively long URL", ErrorUtil.RESP_400);
        }

        URI parsedUri;

        // Normalizes and validates URL syntax
        try {
            parsedUri = new URI(url).normalize();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with malformed URL (" + e.getClass().getName() + ")",
                    ErrorUtil.RESP_400);
        }

        String scheme = parsedUri.getScheme();

        // Prepends https:// for schemeless URLs (e.g., example.com)
        if (scheme == null) {
            try {
                parsedUri = new URI("https://" + parsedUri).normalize();
                parsedUri.toURL();
                scheme = parsedUri.getScheme();
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with malformed schemeless URL (" + e.getClass().getName() + ")",
                        ErrorUtil.RESP_400);
            }
        }

        scheme = scheme.toLowerCase(Locale.ROOT);

        // Rejects unsupported schemes (only http and https allowed)
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with disallowed URL scheme", ErrorUtil.RESP_400);
        }

        String host = parsedUri.getHost();

        // Extracts host from authority if getHost() is null
        if (host == null || host.isBlank()) {
            String authority = parsedUri.getRawAuthority();

            // Rejects requests with no authority/host component
            if (authority == null || authority.isBlank()) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with no host", ErrorUtil.RESP_400);
            }

            // Handle bracketed IPv6 literals (e.g., [::1] or [::1]:8080)
            if (authority.charAt(0) == '[' && authority.contains("]")) {
                int closingBracket = authority.indexOf(']');

                if (closingBracket < 0) {
                    return rejectInvalidRequest(provider, hashedIp, providerName,
                            "Blocked request with malformed IPv6 host", ErrorUtil.RESP_400);
                }

                host = authority.substring(1, closingBracket);
            } else {
                int lastColon = authority.lastIndexOf(':');
                host = lastColon >= 0 ? authority.substring(0, lastColon) : authority;
            }
        }

        // Rejects empty hosts
        if (host.isBlank()) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with empty host", ErrorUtil.RESP_400);
        }

        host = host.toLowerCase(Locale.ROOT);

        // Removes trailing dot(s)
        while (!host.isEmpty() && host.charAt(host.length() - 1) == '.') {
            host = host.substring(0, host.length() - 1);
        }

        // Rejects hosts that are empty after normalization
        if (host.isEmpty()) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with empty host after normalization", ErrorUtil.RESP_400);
        }

        // Reconstructs the URI with the normalized host and scheme
        try {
            int port = parsedUri.getPort();
            String path = parsedUri.getPath();
            String query = parsedUri.getQuery();
            String fragment = parsedUri.getFragment();
            parsedUri = new URI(scheme, null, host, port, path, query, fragment);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request due to error during URI reconstruction (" + e.getClass().getName() + ")",
                    ErrorUtil.RESP_400);
        }

        // Blocks private/internal hosts (string-based checks; IP-level blocking happens
        // inside SSRF_SAFE_DNS_RESOLVER at connection time to prevent DNS rebinding)
        if (IPUtil.isPrivateHost(host, providerName)) {
            return rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request to private/internal host", ErrorUtil.RESP_400);
        }

        // ------------------------------------------------
        // Provider-Specific URL Modifications
        // ------------------------------------------------

        // PrecisionSec only wants the bare domain, no scheme/path/query/fragment
        // Example: https://example.com/some/path?q=1 -> example.com
        if ("PrecisionSec".equals(providerName)) {
            try {
                parsedUri = new URI(parsedUri.getHost());
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request due to error during PrecisionSec URI reconstruction (" + e.getClass().getName() + ")",
                        ErrorUtil.RESP_400);
            }
        }

        // ------------------------------------------------
        // Request Statistics
        // ------------------------------------------------

        RequestStats stats = PROVIDER_STATS.computeIfAbsent(providerName, k -> new RequestStats());
        stats.totalRequestCount.incrementAndGet();
        stats.secondBucket.incrementAndGet();

        // ------------------------------------------------
        // Upstream Request Execution
        // ------------------------------------------------

        // Skips upstream call and returns fake response for stress tests
        if (StressTestUtil.isEnabled()) {
            return ErrorUtil.RESP_200;
        }

        // Sends the normalized URL string to the upstream provider
        String normalizedUrl = parsedUri.toString();
        return executeUpstream(provider, normalizedUrl);
    }

    /**
     * Executes the upstream request to the provider synchronously.
     * <p>
     * Runs on a virtual thread: the blocking {@code HTTP_CLIENT.execute()} call parks
     * the virtual thread during I/O without blocking any platform thread.
     *
     * @param provider      The provider configuration.
     * @param normalizedUrl The validated, normalized URL to check.
     * @return A {@link ResponseEntity} containing either the upstream response body
     *         or an appropriate error body.
     */
    private static ResponseEntity<String> executeUpstream(@NonNull Provider provider,
                                                          @NonNull String normalizedUrl) {
        String method = provider.getMethod();
        String providerName = provider.getName();
        ClassicRequestBuilder requestBuilder;

        // Builds the request based on the provider's specified method (GET or POST).
        if (method.equals("GET")) {
            requestBuilder = ClassicRequestBuilder.get(provider.buildRequestUrl(normalizedUrl));
        } else {
            Map<String, Object> requestBody = provider.buildBody(normalizedUrl);
            String jsonBody = "";

            if (requestBody != null) {
                try {
                    jsonBody = MAPPER.writeValueAsString(requestBody);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.error("[{}] Failed to serialize request body: {}", providerName, e.getMessage());
                    return ErrorUtil.RESP_502;
                }
            }

            requestBuilder = ClassicRequestBuilder.post(provider.buildRequestUrl(normalizedUrl))
                    .setEntity(jsonBody, ContentType.APPLICATION_JSON);
        }

        // Applies provider-specific headers (e.g., API key headers)
        for (Map.Entry<String, String> header : provider.getHeaders().entrySet()) {
            requestBuilder.addHeader(header.getKey(), header.getValue());
        }

        try {
            return HTTP_CLIENT.execute(requestBuilder.build(), (ClassicHttpResponse response) -> {
                int statusCode = response.getCode();
                byte[] responseBytes = EntityUtils.toByteArray(response.getEntity());

                // Rejects non-200 responses with provider-specific logging and error mapping
                if (statusCode != 200) {
                    log.warn("[{}] Upstream request failed with status code: {}", providerName, statusCode);
                    return switch (statusCode) {
                        case 400 -> ErrorUtil.RESP_400;
                        case 404 -> ErrorUtil.RESP_404;
                        case 415 -> ErrorUtil.RESP_415;
                        case 429 -> ErrorUtil.RESP_429;
                        default -> ErrorUtil.RESP_502;
                    };
                }

                if (responseBytes == null || responseBytes.length == 0) {
                    log.warn("[{}] Upstream response was empty", providerName);
                    return ErrorUtil.RESP_502;
                }

                if (responseBytes.length > MAX_RESPONSE_SIZE) {
                    log.warn("[{}] Upstream response exceeded maximum size: {} bytes", providerName, responseBytes.length);
                    return ErrorUtil.RESP_502;
                }

                // Validate that the response is well-formed JSON using a streaming parser.
                // Manually tracks nesting depth as defense-in-depth against CVE-2026-29062.
                try (JsonParser parser = MAPPER.createParser(responseBytes)) {
                    int depth = 0;
                    JsonToken token;

                    while ((token = parser.nextToken()) != null) {
                        if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                            depth++;

                            if (depth > MAX_NESTING_DEPTH) {
                                log.warn("[{}] Upstream response exceeded maximum nesting depth: {}", providerName, depth);
                                return ErrorUtil.RESP_502;
                            }
                        } else if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                            depth--;
                        }
                    }
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.warn("[{}] Failed to parse upstream response as JSON ({})", providerName, e.getClass().getName(), e);
                    return ErrorUtil.RESP_502;
                }

                // Pass through the validated raw bytes as a UTF-8 string
                String responseBody = new String(responseBytes, StandardCharsets.UTF_8);
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(responseBody);
            });
        } catch (SocketTimeoutException | ConnectionRequestTimeoutException e) {
            log.error("[{}] Upstream request timed out: {}", providerName, e.getClass().getName());
            return ErrorUtil.RESP_504;
        } catch (UnknownHostException e) {
            log.error("[{}] Upstream request blocked by SSRF resolver: {}", providerName, e.getMessage());
            return ErrorUtil.RESP_502;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected error during upstream request: {} | {}", providerName, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }

    // -------------------------------------------------------------------------
    // Rate limit helpers
    // -------------------------------------------------------------------------

    /**
     * Checks if the given IP is burst-blocked or has exceeded the burst rate limit.
     * Consumes one token from the burst bucket if not already blocked.
     */
    private static boolean isBurstBlocked(@NonNull Provider provider,
                                          @NonNull String hashedIp,
                                          @NonNull String providerName) {
        String violatorId = provider.getViolatorId(hashedIp);

        if (provider.isBurstBlocked(hashedIp)) {
            log.warn("[{}] RATE LIMIT ACTIVE: Burst | {}", providerName, violatorId);
            return true;
        }

        if (!provider.getBurstBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] RATE LIMIT HIT: Burst | {}", providerName, violatorId);
            provider.blockBurst(hashedIp);
            return true;
        }
        return false;
    }

    /**
     * Checks if the given IP is sustained-blocked or has exceeded the sustained rate limit.
     * Consumes one token from the sustained bucket if not already blocked.
     */
    private static boolean isSustainedBlocked(@NonNull Provider provider,
                                              @NonNull String hashedIp,
                                              @NonNull String providerName) {
        String violatorId = provider.getViolatorId(hashedIp);

        if (provider.isSustainedBlocked(hashedIp)) {
            log.warn("[{}] RATE LIMIT ACTIVE: Sustained | {}", providerName, violatorId);
            return true;
        }

        if (!provider.getSustainedBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] RATE LIMIT HIT: Sustained | {}", providerName, violatorId);
            provider.blockSustained(hashedIp);
            return true;
        }
        return false;
    }

    /**
     * Consumes one token from the invalid-request bucket for the given IP.
     * Blocks the IP if the bucket is exhausted. Logs the rejection reason.
     *
     * @param provider The provider to consume the invalid request token from.
     * @param hashedIp The hashed IP address to check and consume from.
     * @param providerName The provider name for logging purposes.
     * @param logMessage The warning message to log when the request is rejected.
     * @param errorResponse The error response to return when the request is rejected normally.
     * @return {@code errorResponse}, or a 429 if the IP has now been blocked.
     */
    private static ResponseEntity<String> rejectInvalidRequest(@NonNull Provider provider,
                                                               @NonNull String hashedIp,
                                                               @NonNull String providerName,
                                                               @NonNull String logMessage,
                                                               @NonNull ResponseEntity<String> errorResponse) {
        if (!provider.getInvalidRequestBucket(hashedIp).tryConsume(1)) {
            String violatorId = provider.getViolatorId(hashedIp);
            log.warn("[{}] RATE LIMIT HIT: Invalid request | {}", providerName, violatorId);
            provider.blockInvalidRequest(hashedIp);
            return ErrorUtil.RESP_429;
        }

        // If the IP is not yet blocked, log the reason and return the provided error response
        log.warn("[{}] {}", providerName, logMessage);
        return errorResponse;
    }
}
