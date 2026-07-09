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

import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.AbstractDNSProvider;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.services.CircuitBreakerService;
import net.foulest.ospreyproxy.services.MetricsService;
import net.foulest.ospreyproxy.util.*;
import net.foulest.ospreyproxy.util.list.Descriptor;
import net.foulest.ospreyproxy.util.list.LocalListUtil;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Central controller for all incoming requests. Performs IP extraction, rate limiting, body validation,
 * URL normalization and SSRF checks, and upstream request execution for all providers.
 */
@Slf4j
@RestController
public class ProxyHandler {

    // HTTP/1.1 client for upstream API requests (some providers don't support HTTP/2)
    // 200 max conn. total, 100 max conn. per route
    // 5s connect timeout, 5s connection request timeout, 7s response timeout
    private static final CloseableHttpClient HTTP_CLIENT = HttpClients.custom()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setDnsResolver(NetworkUtil.DNS_RESOLVER)
                    .setMaxConnTotal(200)
                    .setMaxConnPerRoute(100)
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(Timeout.ofSeconds(5))
                            .setTimeToLive(Timeout.ofMinutes(5))
                            .setValidateAfterInactivity(TimeValue.ofSeconds(5))
                            .build())
                    .build())
            .setDefaultRequestConfig(RequestConfig.custom()
                    .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                    .setResponseTimeout(Timeout.ofSeconds(7))
                    .build())
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .build();

    // Maximum number of bytes to read from an upstream response (1 MB)
    private static final int MAX_RESPONSE_BYTES = 1_048_576;

    // All providers keyed by endpoint name for O(1) dispatch and O(1) DNS provider lookup
    private final Map<String, Provider> providersByEndpointName;

    // Injected services
    private final MetricsService metrics;
    private final CircuitBreakerService circuitBreaker;

    // Collapses concurrent duplicate lookups (same provider + same key) into a single execution,
    // so a burst of identical requests doesn't fan out into redundant upstream calls or log lines
    private final RequestCoalescer<ResponseEntity<String>> coalescer = new RequestCoalescer<>();

    /**
     * Constructor for ProxyHandler. Spring injects every {@link Provider} bean automatically.
     *
     * @param providers All registered providers, injected by Spring.
     * @param metrics Micrometer-backed metrics service, injected by Spring.
     * @param circuitBreaker Resilience4j circuit breaker service, injected by Spring.
     */
    public ProxyHandler(@NonNull List<Provider> providers,
                        @NonNull MetricsService metrics,
                        @NonNull CircuitBreakerService circuitBreaker) {
        this.metrics = metrics;
        this.circuitBreaker = circuitBreaker;

        // Build the provider map for O(1) lookup by endpoint name
        providersByEndpointName = providers.stream()
                .collect(Collectors.toMap(Provider::getEndpointName, Function.identity()));

        // Pre-warm Jackson type metadata
        JacksonUtil.MAPPER.constructType(Map.class);
        JacksonUtil.MAPPER.constructType(String.class);
        JacksonUtil.MAPPER.constructType(Object.class);
    }

    /**
     * Releases shared resources owned or coordinated by ProxyHandler.
     */
    @PreDestroy
    public void destroy() {
        try {
            HTTP_CLIENT.close();
        } catch (IOException e) {
            log.warn("Failed to close upstream API HTTP client: {} ({})", e.getMessage(), e.getClass().getName());
        }

        AbstractDNSProvider.closeSharedClients();
    }

    /**
     * Dynamic endpoint for all providers.
     * Routes to the provider whose {@link Provider#getEndpointName()} matches {@code providerName}.
     * Keep @RequestBody(required = false) for rate-limiting.
     *
     * @param providerName The path variable extracted from the URL, used to look up the provider.
     * @param body The raw request body bytes, passed to the provider for validation and forwarding.
     * @param request The incoming servlet request, used for IP extraction and header validation.
     * @return A {@link ResponseEntity} containing the provider's response or an appropriate error status.
     */
    @PostMapping(value = "/{providerName}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleProvider(@PathVariable String providerName,
                                                 @RequestBody(required = false) byte[] body,
                                                 @NonNull HttpServletRequest request) {
        Provider provider = providersByEndpointName.get(providerName);

        if (provider == null) {
            metrics.recordBlocked("unknown", 404);
            return ErrorUtil.RESP_404;
        }
        return proxyRequest(body, request, provider);
    }

    /**
     * Core method implementing all proxy logic: IP extraction, rate limiting,
     * body parsing and validation, URL normalization and SSRF checks, and
     * upstream request execution.
     * <p>
     * Runs sequentially on a virtual thread. All blocking calls (body read,
     * upstream HTTP) park the virtual thread rather than blocking a platform thread.
     * <p>
     * All validation steps throw {@link StatusCodeException} on failure; a single
     * catch block at the top level converts them to the appropriate response.
     *
     * @param bodyBytes Raw request body bytes delivered by Spring MVC.
     * @param request   The incoming servlet request (used for IP extraction).
     * @param provider  The upstream provider to forward to.
     * @return A {@link ResponseEntity} to return to the client.
     */
    private ResponseEntity<String> proxyRequest(byte[] bodyBytes,
                                                @NonNull HttpServletRequest request,
                                                @NonNull Provider provider) {
        String providerName = provider.getDisplayName();
        String endpointName = provider.getEndpointName();

        try {
            if (!provider.isEnabled()) {
                metrics.recordBlocked(providerName, 503);
                return ErrorUtil.RESP_503;
            }

            String hashedIp = RequestUtil.validateIP(request, provider, providerName);
            Map<String, String> incoming = RequestUtil.validateBody(bodyBytes, provider, providerName, hashedIp);
            String url = Objects.toString(incoming.get("url"), "").strip();
            URI parsedUri = RequestUtil.validateURI(url, provider, providerName, hashedIp);
            String scheme = RequestUtil.validateScheme(parsedUri, provider, providerName, hashedIp);
            String host = RequestUtil.validateHost(parsedUri, provider, providerName, hashedIp);
            parsedUri = RequestUtil.reconstructURI(parsedUri, host, scheme, provider, providerName, hashedIp);

            Descriptor descriptor = LocalListUtil.findByEndpointName(endpointName);
            boolean stripToBareHost = provider.isStripToBareHost();
            boolean hostKeyed = provider instanceof AbstractDNSProvider || provider.isStripToHost() || stripToBareHost;
            String hostKey = stripToBareHost ? RequestUtil.getBareHost(host) : host;
            String lookupKey;

            if (hostKeyed) {
                lookupKey = hostKey;
            } else {
                URI canonicalUri = RequestUtil.reconstructURI(parsedUri, host, "https", provider, providerName, hashedIp);
                lookupKey = canonicalUri.toString();
            }

            if (descriptor == null && provider instanceof AbstractProvider ap) {
                LookupVerdict cached = ap.getCachedResult(lookupKey);

                if (cached != null) {
                    metrics.recordRequest(providerName);
                    metrics.recordCacheHit();
                    return resultResponse(cached, providerName);
                }

                metrics.recordCacheMiss();
            }

            if (NetworkUtil.isPrivateHost(host)) {
                RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "");
                return ErrorUtil.RESP_400;
            }

            metrics.recordRequest(providerName);

            // One key per (provider, lookup target). Concurrent duplicates share a single execution;
            // the NUL separator can't appear in an endpoint name or normalized host/URL, so it's an
            // unambiguous delimiter between the two parts
            String coalesceKey = endpointName + '\u0000' + lookupKey;

            if (provider instanceof AbstractDNSProvider dnsProvider) {
                return coalescer.get(coalesceKey, () -> {
                    LookupVerdict verdict = dnsProvider.lookupAndCache(lookupKey);

                    if (verdict.isRateLimited()) {
                        return ErrorUtil.RESP_429;
                    }

                    // Log the domain if the result is MALICIOUS or PHISHING for false-positive monitoring.
                    // This is never logged for benign results, and logs aren't stored to disk or sent to external systems.
                    if (verdict.primary() == LookupResult.MALICIOUS || verdict.primary() == LookupResult.PHISHING) {
                        log.warn("[{}] Result for '{}': {}", dnsProvider.getDisplayName(), host, verdict.primary().getValue());
                    }
                    return resultResponse(verdict, providerName);
                });
            }

            if (descriptor != null) {
                return coalescer.get(coalesceKey, () -> {
                    LookupVerdict verdict = LookupVerdict.of(LocalListUtil.lookup(descriptor, lookupKey));

                    // Log the domain if the result is MALICIOUS or PHISHING for false-positive monitoring.
                    // This is never logged for benign results, and logs aren't stored to disk or sent to external systems.
                    if (verdict.primary() == LookupResult.MALICIOUS || verdict.primary() == LookupResult.PHISHING) {
                        log.warn("[{}] Result for '{}': {}", descriptor.getShortName(), host, verdict.primary().getValue());
                    }
                    return resultResponse(verdict, providerName);
                });
            }
            return coalescer.get(coalesceKey, () -> executeUpstream(provider, providerName, lookupKey));
        } catch (StatusCodeException e) {
            ResponseEntity<String> status = e.getStatus();
            int code = status.getStatusCode().value();
            metrics.recordBlocked(providerName, code);
            return status;
        }
    }

    /**
     * Executes an upstream API provider request and returns the interpreted result as JSON.
     * <p>
     * The result cache has already been probed (and missed) in {@code proxyRequest},
     * so this method only handles the circuit breaker, the upstream HTTP call,
     * response interpretation, and the cache write.
     *
     * @param provider The provider configuration.
     * @param providerName The provider display name for logging.
     * @param forwardUrl The validated string to look up (host or normalized URL).
     * @return A {@link ResponseEntity} containing {@code {"result": "<value>"}},
     *         or an appropriate error response on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private ResponseEntity<String> executeUpstream(@NonNull Provider provider,
                                                   @NonNull String providerName,
                                                   @NonNull String forwardUrl) {
        // Skip the upstream call if the circuit breaker is open (too many recent failures)
        if (circuitBreaker.isOpen(providerName)) {
            return ErrorUtil.RESP_429;
        }

        String requestUrl = provider.buildRequestUrl(forwardUrl);
        ClassicRequestBuilder requestBuilder = ClassicRequestBuilder
                .create(provider.getMethod().name())
                .setUri(requestUrl);

        Map<String, Object> requestBody = provider.buildBody(forwardUrl);

        if (requestBody != null) {
            String jsonBody;

            try {
                jsonBody = JacksonUtil.MAPPER.writeValueAsString(requestBody);
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                log.error("[{}] Failed to serialize request body: {} ({})",
                        providerName, e.getMessage(), e.getClass().getName());
                return ErrorUtil.RESP_502;
            }

            requestBuilder.setEntity(jsonBody, ContentType.APPLICATION_JSON);
        }

        // Applies provider-specific headers (e.g., API key headers)
        for (Map.Entry<String, String> header : provider.getHeaders().entrySet()) {
            requestBuilder.addHeader(header.getKey(), header.getValue());
        }

        long callStart = System.nanoTime();

        try {
            ClassicHttpRequest httpRequest = requestBuilder.build();

            return HTTP_CLIENT.execute(httpRequest, (ClassicHttpResponse response) -> {
                long durationNanos = System.nanoTime() - callStart;
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                byte[] responseBytes;

                try {
                    responseBytes = EntityUtils.toByteArray(entity, MAX_RESPONSE_BYTES + 1);
                } catch (IOException e) {
                    EntityUtils.consumeQuietly(entity);
                    log.error("[{}] Failed to read response body: {}", providerName, e.getClass().getName());
                    return ErrorUtil.RESP_502;
                }

                if (responseBytes != null && responseBytes.length > MAX_RESPONSE_BYTES) {
                    log.warn("[{}] Upstream response exceeded {} bytes; rejecting", providerName, MAX_RESPONSE_BYTES);
                    return ErrorUtil.RESP_502;
                }

                // A 404 from providers that report misses this way (e.g. BforeAI) is a valid
                // "not in database" answer, not a failure: fall through to interpret-and-cache
                boolean notFoundIsValid = statusCode == 404 && provider.isNotFoundValidResponse();

                // Rejects non-200 responses with provider-specific error mapping
                if (statusCode != 200 && !notFoundIsValid) {
                    log.warn("[{}] Upstream request failed with status code: {}", providerName, statusCode);

                    return switch (statusCode) {
                        case 400 -> {
                            log.warn("[{}] Upstream returned 400 with body: {}", providerName, new String(responseBytes, StandardCharsets.UTF_8));
                            yield ErrorUtil.RESP_400;
                        }

                        case 401, 498 -> {
                            log.error("[{}] Upstream rejected API key (HTTP {})", providerName, statusCode);
                            yield ErrorUtil.RESP_502;
                        }

                        case 404 -> ErrorUtil.RESP_404;
                        case 415 -> ErrorUtil.RESP_415;

                        case 429 -> {
                            circuitBreaker.recordFailure(providerName, durationNanos, new RuntimeException("HTTP 429"));
                            yield ErrorUtil.RESP_429;
                        }

                        default -> {
                            if (statusCode >= 500) {
                                circuitBreaker.recordFailure(providerName, durationNanos, new RuntimeException("HTTP " + statusCode));
                            }
                            yield ErrorUtil.RESP_502;
                        }
                    };
                }

                // Rejects empty responses
                if (responseBytes == null || responseBytes.length == 0) {
                    log.error("[{}] Upstream response was empty", providerName);
                    return ErrorUtil.RESP_502;
                }

                LookupVerdict verdict = provider.interpretAll(responseBytes, forwardUrl);

                // Log the domain if the result is MALICIOUS or PHISHING for false-positive monitoring.
                // This is never logged for benign results, and logs aren't stored to disk or sent to external systems.
                if (verdict.primary() == LookupResult.MALICIOUS || verdict.primary() == LookupResult.PHISHING) {
                    log.warn("[{}] Result for '{}': {}", providerName, forwardUrl, verdict.primary().getValue());
                }

                // Record success so the circuit breaker counts this call in its sliding window
                circuitBreaker.recordSuccess(providerName, durationNanos);

                // Caches the result for future requests
                if (provider instanceof AbstractProvider ap) {
                    ap.putCachedResult(forwardUrl, verdict);
                }
                return resultResponse(verdict, providerName);
            });
        } catch (SocketTimeoutException | ConnectionRequestTimeoutException | NoHttpResponseException e) {
            long durationNanos = System.nanoTime() - callStart;
            log.error("[{}] Upstream request timed out ({})", providerName, e.getClass().getName());
            circuitBreaker.recordFailure(providerName, durationNanos, e);
            return ErrorUtil.RESP_504;
        } catch (UnknownHostException e) {
            log.error("[{}] Upstream request blocked by SSRF resolver", providerName, e);
            return ErrorUtil.RESP_502;
        } catch (SocketException e) {
            log.error("[{}] Upstream request failed due to socket error ({})", providerName, e.getClass().getName(), e);
            return ErrorUtil.RESP_502;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected error during upstream request ({})", providerName, e.getClass().getName(), e);
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Serializes a {@link LookupVerdict} into a JSON response.
     * <p>
     * Emits both a backward-compatible {@code "result"} scalar (the single most severe
     * {@link LookupResult}, for clients that expect one value) and a {@code "results"} array
     * containing every result in the verdict, severity-ordered. Single-result providers therefore
     * produce {@code {"result":"x","results":["x"]}}; multi-category providers such as AlphaMountain
     * produce {@code {"result":"malicious","results":["malicious","newly_registered",...]}}.
     *
     * @param verdict      The verdict to serialize.
     * @param providerName The provider display name for error logging.
     * @return A {@link ResponseEntity} with the JSON body, or a 502 on serialization failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private static @NonNull ResponseEntity<String> resultResponse(@NonNull LookupVerdict verdict,
                                                                  @NonNull String providerName) {
        try {
            Map<String, Object> payload = LinkedHashMap.newLinkedHashMap(2);
            payload.put("result", verdict.primary().getValue());
            payload.put("results", verdict.values());

            String responseBody = JacksonUtil.MAPPER.writeValueAsString(payload);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(responseBody);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize result: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }
}
