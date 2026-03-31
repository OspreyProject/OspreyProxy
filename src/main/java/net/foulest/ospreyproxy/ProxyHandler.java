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
import net.foulest.ospreyproxy.providers.AbstractDNSProvider;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.providers.other.CheckEndpoint;
import net.foulest.ospreyproxy.result.LookupResult;
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
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
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
                            .build())
                    .build())
            .setDefaultRequestConfig(RequestConfig.custom()
                    .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                    .setResponseTimeout(Timeout.ofSeconds(7))
                    .build())
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .build();

    // Virtual thread executor for parallel /check endpoint lookups
    private static final Executor VIRTUAL_THREAD_EXECUTOR =
            Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("check-", 0).factory());

    // All providers keyed by endpoint name for O(1) dispatch and O(1) DNS provider lookup
    private final Map<String, Provider> providersByEndpointName;

    // CheckEndpoint provider reference, kept for API-key validation
    private final CheckEndpoint checkEndpoint;

    /**
     * Constructor for ProxyHandler. Spring injects every {@link Provider} bean automatically.
     */
    public ProxyHandler(@NonNull List<Provider> providers, @NonNull CheckEndpoint checkEndpoint) {
        this.checkEndpoint = checkEndpoint;

        providersByEndpointName = providers.stream()
                .collect(Collectors.toMap(Provider::getEndpointName, Function.identity()));

        // Pre-warm Jackson type metadata
        JacksonUtil.MAPPER.constructType(Map.class);
        JacksonUtil.MAPPER.constructType(String.class);
        JacksonUtil.MAPPER.constructType(Object.class);
    }

    /**
     * Dynamic endpoint for all non-CheckEndpoint providers.
     * Routes to the provider whose {@link Provider#getEndpointName()} matches {@code providerName}.
     * Keep @RequestBody(required = false) for rate-limiting.
     */
    @PostMapping(value = "/{providerName}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleProvider(@PathVariable String providerName,
                                                 @RequestBody(required = false) byte[] body,
                                                 @NonNull HttpServletRequest request) {
        Provider provider = providersByEndpointName.get(providerName);

        if (provider == null || provider instanceof CheckEndpoint) {
            return ErrorUtil.RESP_404;
        }
        return proxyRequest(body, request, provider);
    }

    /**
     * Dedicated /check endpoint for aggregate lookups to all non-premium providers.
     * Keep @RequestBody(required = false) for rate-limiting.
     */
    @PostMapping(value = "/check",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handleCheckEndpoint(@RequestBody(required = false) byte[] body,
                                                      @NonNull HttpServletRequest request) {
        return proxyRequest(body, request, checkEndpoint);
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
            String hashedIp = RequestUtil.validateIP(request, provider, providerName);

            if (!provider.isEnabled()) {
                return ErrorUtil.RESP_503;
            }

            Map<String, String> incoming = RequestUtil.validateBody(bodyBytes, provider, providerName, hashedIp);

            if (provider instanceof CheckEndpoint) {
                RequestUtil.validateApiKeyHeader(request, provider, providerName, hashedIp);
            }

            @SuppressWarnings("NestedMethodCall")
            String url = Objects.toString(incoming.get("url"), "").trim();
            URI parsedUri = RequestUtil.validateURI(url, provider, providerName, hashedIp);
            String scheme = RequestUtil.validateScheme(parsedUri, provider, providerName, hashedIp);
            String host = RequestUtil.validateHost(parsedUri, provider, providerName, hashedIp);
            parsedUri = RequestUtil.reconstructURI(parsedUri, host, scheme, provider, providerName, hashedIp);
            RequestUtil.validateDNS(parsedUri, host, provider, providerName, hashedIp);

            StatsUtil.recordRequest(providerName);
            String normalizedUrl = parsedUri.toString();

            // The /check executes a custom aggregate lookup that fans out to multiple DNS providers
            // and local lists in parallel, then assembles a custom JSON response.
            if (provider instanceof CheckEndpoint) {
                return executeAggregateCheck(host, providerName);
            }

            // DNS providers submit only the hostname upstream.
            // doLookup() is self-contained; cachedLookup() handles the cache transparently.
            if (provider instanceof AbstractDNSProvider dnsProvider) {
                LookupResult result = dnsProvider.cachedLookup(host);
                return resultResponse(result, providerName, host);
            }

            // Local list providers check against an in-memory domain set.
            // doLookup() is self-contained; cachedLookup() handles the cache transparently.
            Descriptor listDescriptor = LocalListUtil.findByEndpointName(endpointName);
            if (listDescriptor != null) {
                LookupResult result = provider.cachedLookup(host);
                return resultResponse(result, providerName, host);
            }

            // API providers require HTTP_CLIENT which lives here, so execution stays in
            // executeUpstream. The cache read/write is done there via getCachedResult /
            // putCachedResult rather than through cachedLookup.
            String forwardUrl = provider.stripToHost() ? host : normalizedUrl;
            return executeUpstream(provider, providerName, forwardUrl);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }
    }

    /**
     * Executes the CheckEndpoint aggregate lookup synchronously.
     *
     * @param host         The validated, normalized host to lookup.
     * @param providerName The display name of the provider, for logging.
     * @return A {@link ResponseEntity} containing the JSON result map, or a 502 on serialization failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private ResponseEntity<String> executeAggregateCheck(@NonNull String host,
                                                         @NonNull String providerName) {
        // Providers to check
        AbstractDNSProvider adGuard = getDnsProvider("adguard-security");
        AbstractDNSProvider certEE = getDnsProvider("cert-ee");
        AbstractDNSProvider cleanBrowsing = getDnsProvider("cleanbrowsing-security");
        AbstractDNSProvider cloudflare = getDnsProvider("cloudflare-security");
        AbstractDNSProvider controlD = getDnsProvider("controld-security");
        AbstractDNSProvider quad9 = getDnsProvider("quad9");
        AbstractDNSProvider switchCh = getDnsProvider("switch-ch");
        Provider phishDestroy = providersByEndpointName.get(Descriptor.PHISH_DESTROY.endpointName);
        Provider phishingDatabase = providersByEndpointName.get(Descriptor.PHISHING_DATABASE.endpointName);

        // Futures for parallel execution of all checks
        CompletableFuture<LookupResult> adGuardFuture = CompletableFuture.supplyAsync(() -> adGuard.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> certEEFuture = CompletableFuture.supplyAsync(() -> certEE.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> cleanBrowsingFuture = CompletableFuture.supplyAsync(() -> cleanBrowsing.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> cloudflareFuture = CompletableFuture.supplyAsync(() -> cloudflare.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> controlDFuture = CompletableFuture.supplyAsync(() -> controlD.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> quad9Future = CompletableFuture.supplyAsync(() -> quad9.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> switchChFuture = CompletableFuture.supplyAsync(() -> switchCh.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> phishDestroyFuture = phishDestroy != null ? CompletableFuture.supplyAsync(() -> phishDestroy.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR) : CompletableFuture.completedFuture(LookupResult.FAILED);
        CompletableFuture<LookupResult> phishingDatabaseFuture = phishingDatabase != null ? CompletableFuture.supplyAsync(() -> phishingDatabase.cachedLookup(host), VIRTUAL_THREAD_EXECUTOR) : CompletableFuture.completedFuture(LookupResult.FAILED);

        // Wait for all futures to complete
        try {
            CompletableFuture.allOf(
                    adGuardFuture,
                    certEEFuture,
                    cleanBrowsingFuture,
                    cloudflareFuture,
                    controlDFuture,
                    phishDestroyFuture,
                    phishingDatabaseFuture,
                    quad9Future,
                    switchChFuture
            ).orTimeout(700, TimeUnit.MILLISECONDS).join();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
        }

        boolean adGuardResult = safeGet(adGuardFuture, providerName, "adGuardSecurity") == LookupResult.MALICIOUS;
        boolean certEEResult = safeGet(certEEFuture, providerName, "certEE") == LookupResult.MALICIOUS;
        boolean cleanBrowsingResult = safeGet(cleanBrowsingFuture, providerName, "cleanBrowsingSecurity") == LookupResult.MALICIOUS;
        boolean cloudflareResult = safeGet(cloudflareFuture, providerName, "cloudflareSecurity") == LookupResult.MALICIOUS;
        boolean controlDResult = safeGet(controlDFuture, providerName, "controlDSecurity") == LookupResult.MALICIOUS;
        boolean phishDestroyResult = safeGet(phishDestroyFuture, providerName, "phishDestroy") == LookupResult.PHISHING;
        boolean phishingDatabaseResult = safeGet(phishingDatabaseFuture, providerName, "phishingDatabase") == LookupResult.PHISHING;
        boolean quad9Result = safeGet(quad9Future, providerName, "quad9") == LookupResult.MALICIOUS;
        boolean switchChResult = safeGet(switchChFuture, providerName, "switchCH") == LookupResult.MALICIOUS;

        List<Boolean> results = List.of(
                adGuardResult,
                certEEResult,
                cleanBrowsingResult,
                cloudflareResult,
                controlDResult,
                phishDestroyResult,
                phishingDatabaseResult,
                quad9Result,
                switchChResult
        );

        int blockedCount = 0;
        for (boolean result : results) {
            if (result) {
                blockedCount++;
            }
        }

        String confidence = "unknown";

        // Determines confidence
        if (blockedCount == 1) {
            confidence = "low";
        } else if (blockedCount == 2) {
            confidence = "medium";
        } else if (blockedCount == 0 || blockedCount >= 3) {
            confidence = "high";
        }

        // Build the JSON map
        Map<String, Object> resultMap = new LinkedHashMap<>();
        resultMap.put("host", host);
        resultMap.put("detections", blockedCount);
        resultMap.put("confidence", confidence);

        // "providers" subkey
        Map<String, Boolean> providersMap = new LinkedHashMap<>();
        providersMap.put("adGuard", adGuardResult);
        providersMap.put("certEE", certEEResult);
        providersMap.put("cleanBrowsing", cleanBrowsingResult);
        providersMap.put("cloudflare", cloudflareResult);
        providersMap.put("controlD", controlDResult);
        providersMap.put("phishDestroy", phishDestroyResult);
        providersMap.put("phishingDatabase", phishingDatabaseResult);
        providersMap.put("quad9", quad9Result);
        providersMap.put("switchCH", switchChResult);

        resultMap.put("providers", providersMap);

        try {
            String responseBody = JacksonUtil.MAPPER.writeValueAsString(resultMap);
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(responseBody);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize result map for '{}': {} ({})",
                    providerName, host, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Executes an upstream API provider request and returns the interpreted result as JSON.
     *
     * @param provider The provider configuration.
     * @param providerName The provider display name for logging.
     * @param forwardUrl The validated string to look up (host or normalized URL).
     * @return A {@link ResponseEntity} containing {@code {"result": "<value>"}},
     *         or an appropriate error response on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private static ResponseEntity<String> executeUpstream(@NonNull Provider provider,
                                                          @NonNull String providerName,
                                                          @NonNull String forwardUrl) {
        // Returns the cached result if present
        if (provider instanceof AbstractProvider ap) {
            LookupResult cached = ap.getCachedResult(forwardUrl);

            if (cached != null) {
                return resultResponse(cached, providerName, forwardUrl);
            }
        }

        Method method = provider.getMethod();
        ClassicRequestBuilder requestBuilder;
        String requestUrl = provider.buildRequestUrl(forwardUrl);

        // Builds the request based on the provider's specified method (GET or POST)
        if (method == Method.GET) {
            requestBuilder = ClassicRequestBuilder.get(requestUrl);
        } else {
            Map<String, Object> requestBody = provider.buildBody(forwardUrl);
            String jsonBody = "";

            // buildBody() returns null for GET providers;
            // POST providers (e.g. AlphaMountain) return a populated map.
            if (requestBody != null) {
                try {
                    jsonBody = JacksonUtil.MAPPER.writeValueAsString(requestBody);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.error("[{}] Failed to serialize request body for '{}': {} ({})",
                            providerName, forwardUrl, e.getMessage(), e.getClass().getName());
                    return ErrorUtil.RESP_502;
                }
            }

            requestBuilder = ClassicRequestBuilder.post(requestUrl).setEntity(jsonBody, ContentType.APPLICATION_JSON);
        }

        // Applies provider-specific headers (e.g., API key headers)
        for (Map.Entry<String, String> header : provider.getHeaders().entrySet()) {
            requestBuilder.addHeader(header.getKey(), header.getValue());
        }

        try {
            ClassicHttpRequest httpRequest = requestBuilder.build();

            return HTTP_CLIENT.execute(httpRequest, (ClassicHttpResponse response) -> {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                byte[] responseBytes = EntityUtils.toByteArray(entity, 10_000);

                // Rejects non-200 responses with provider-specific logging and error mapping
                if (statusCode != 200) {
                    if (statusCode == 400) {
                        log.warn("[{}] Upstream request failed with status code: 400 ({})", providerName, forwardUrl);
                    } else {
                        log.warn("[{}] Upstream request failed with status code: {}", providerName, statusCode);
                    }

                    return switch (statusCode) {
                        case 400 -> ErrorUtil.RESP_400;
                        case 401, 498 -> ErrorUtil.RESP_401;
                        case 404 -> ErrorUtil.RESP_404;
                        case 415 -> ErrorUtil.RESP_415;
                        case 429 -> ErrorUtil.RESP_429;
                        default -> ErrorUtil.RESP_502;
                    };
                }

                // Rejects empty responses
                if (responseBytes == null || responseBytes.length == 0) {
                    log.error("[{}] Upstream response was empty", providerName);
                    return ErrorUtil.RESP_502;
                }

                LookupResult result = provider.interpret(responseBytes, forwardUrl);

                // Caches the result for future requests
                if (provider instanceof AbstractProvider ap) {
                    ap.putCachedResult(forwardUrl, result);
                }
                return resultResponse(result, providerName, forwardUrl);
            });
        } catch (SocketTimeoutException | ConnectionRequestTimeoutException | NoHttpResponseException e) {
            log.error("[{}] Upstream request timed out: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_504;
        } catch (UnknownHostException e) {
            log.error("[{}] Upstream request blocked by SSRF resolver: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected error during upstream request: {} ({})", providerName, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Serializes a {@link LookupResult} into a {@code {"result": "<value>"}} JSON response.
     * Centralizes the response-building pattern shared by all execute paths.
     *
     * @param result       The result to serialize.
     * @param providerName The provider display name for error logging.
     * @param lookupStr    The lookup string (host or URL) for error logging.
     * @return A {@link ResponseEntity} with the JSON body, or a 502 on serialization failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private static @NonNull ResponseEntity<String> resultResponse(@NonNull LookupResult result,
                                                                  @NonNull String providerName,
                                                                  @NonNull String lookupStr) {
        try {
            String responseBody = JacksonUtil.MAPPER.writeValueAsString(
                    Map.of("result", result.getValue())
            );
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(responseBody);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize result for '{}': {} ({})",
                    providerName, lookupStr, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Retrieves the result of a {@link CompletableFuture}, returning {@link LookupResult#FAILED}
     * if the future completed exceptionally or was canceled.
     *
     * @param future       The future to harvest.
     * @param providerName The provider name for logging context.
     * @param sourceName   The source name for logging context.
     * @return The future's result, or {@link LookupResult#FAILED} on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private static LookupResult safeGet(@NonNull CompletableFuture<LookupResult> future,
                                        @NonNull String providerName,
                                        @NonNull String sourceName) {
        try {
            return future.get();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Source '{}' did not complete in time or failed: {} ({})",
                    providerName, sourceName, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }

    /**
     * Looks up a DNS provider by endpoint name from the provider map.
     * Uses O(1) map lookup rather than a linear scan of a separate list.
     *
     * @param endpointName The {@link Provider#getEndpointName()} value to look up.
     * @return The matching {@link AbstractDNSProvider}.
     * @throws IllegalStateException If no DNS provider with the given short name is registered.
     */
    private @NonNull AbstractDNSProvider getDnsProvider(@NonNull String endpointName) {
        Provider provider = providersByEndpointName.get(endpointName);

        if (!(provider instanceof AbstractDNSProvider dnsProvider)) {
            throw new IllegalStateException("No DNS provider registered with endpoint name: " + endpointName);
        }
        return dnsProvider;
    }
}
