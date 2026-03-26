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
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.providers.other.PhishingBox;
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
 * REST controller for all proxy endpoints.
 * <p>
 * Providers are injected as a {@link List} by Spring; a single dynamic endpoint
 * dispatches to the correct provider by short name. PhishingBox uses a dedicated
 * endpoint that fans out to selected DNS providers and local lists in parallel.
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

    // Virtual thread executor for parallel PhishingBox checks
    private static final Executor VIRTUAL_THREAD_EXECUTOR =
            Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("phishingbox-", 0).factory());

    // All providers keyed by short name for O(1) dispatch and O(1) DNS provider lookup
    private final Map<String, Provider> providersByEndpointName;

    // PhishingBox provider reference, kept for API-key validation
    private final PhishingBox phishingBox;

    /**
     * Constructor for ProxyHandler. Spring injects every {@link Provider} bean automatically.
     */
    public ProxyHandler(@NonNull List<Provider> providers, @NonNull PhishingBox phishingBox) {
        this.phishingBox = phishingBox;

        providersByEndpointName = providers.stream()
                .collect(Collectors.toMap(Provider::getEndpointName, Function.identity()));

        // Pre-warm Jackson type metadata
        JacksonUtil.MAPPER.constructType(Map.class);
        JacksonUtil.MAPPER.constructType(String.class);
        JacksonUtil.MAPPER.constructType(Object.class);
    }

    /**
     * Dynamic endpoint for all non-PhishingBox providers.
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

        if (provider == null || provider instanceof PhishingBox) {
            return ErrorUtil.RESP_404;
        }
        return proxyRequest(body, request, provider);
    }

    /**
     * Dedicated endpoint for PhishingBox.
     * Keep @RequestBody(required = false) for rate-limiting.
     */
    @PostMapping(value = "/phishingbox",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handlePhishingBox(@RequestBody(required = false) byte[] body,
                                                    @NonNull HttpServletRequest request) {
        return proxyRequest(body, request, phishingBox);
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

            if (provider instanceof PhishingBox) {
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

            // PhishingBox executes a custom aggregate lookup that fans out to multiple DNS providers
            // and local lists in parallel, then assembles a custom JSON response.
            if (provider instanceof PhishingBox) {
                return executePhishingBox(host, providerName);
            }

            // DNS providers execute their lookup() directly and return a simple result JSON.
            if (provider instanceof AbstractDNSProvider dnsProvider) {
                return executeDnsProvider(dnsProvider, host);
            }

            // Local list providers look up the host against an in-memory domain set.
            Descriptor listDescriptor = LocalListUtil.findByEndpointName(endpointName);
            if (listDescriptor != null) {
                return executeLocalList(listDescriptor, host);
            }

            // API providers that only accept a bare domain (no scheme/path/query/fragment)
            String forwardUrl = provider.stripToHost() ? host : normalizedUrl;
            return executeUpstream(provider, providerName, forwardUrl);
        } catch (StatusCodeException e) {
            return e.getStatus();
        }
    }

    /**
     * Executes a DNS provider lookup and wraps the result as a simple JSON object.
     *
     * @param provider The DNS provider to lookup with.
     * @param host     The validated, normalized host to lookup.
     * @return A {@link ResponseEntity} containing {@code {"result": "<value>"}}.
     */
    @SuppressWarnings("NestedMethodCall")
    private static ResponseEntity<String> executeDnsProvider(@NonNull AbstractDNSProvider provider,
                                                             @NonNull String host) {
        LookupResult result = provider.lookup(host);
        String providerName = provider.getDisplayName();

        try {
            String responseBody = JacksonUtil.MAPPER.writeValueAsString(
                    Map.of("result", result.getValue())
            );
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(responseBody);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize DNS result for '{}': {} ({})",
                    providerName, host, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Executes a local list lookup and wraps the result as a simple JSON object.
     * <p>
     * No upstream request is made; the check is performed entirely against the in-memory
     * domain set maintained by {@link LocalListUtil}.
     *
     * @param descriptor The list descriptor to look up against.
     * @param host       The validated, normalized host to lookup.
     * @return A {@link ResponseEntity} containing {@code {"result": "<value>"}}.
     */
    @SuppressWarnings("NestedMethodCall")
    private static ResponseEntity<String> executeLocalList(@NonNull Descriptor descriptor,
                                                           @NonNull String host) {
        LookupResult result = LocalListUtil.lookupHost(descriptor, host);

        try {
            String responseBody = JacksonUtil.MAPPER.writeValueAsString(
                    Map.of("result", result.getValue())
            );
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(responseBody);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize local list result for '{}': {} ({})",
                    descriptor.shortName, host, e.getMessage(), e.getClass().getName());
            return ErrorUtil.RESP_502;
        }
    }

    /**
     * Executes the PhishingBox aggregate lookup synchronously.
     *
     * @param host The validated, normalized host to lookup.
     * @param providerName The display name of the provider, for logging.
     * @return A {@link ResponseEntity} containing the JSON result map, or a 502 on serialization failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private ResponseEntity<String> executePhishingBox(@NonNull String host,
                                                      @NonNull String providerName) {
        // DNS provider fan-out (security-focused providers only)
        CompletableFuture<LookupResult> adGuardFuture = supplyCheck(getDnsProvider("adguard-security"), host);
        CompletableFuture<LookupResult> cleanBrowsingFuture = supplyCheck(getDnsProvider("cleanbrowsing-security"), host);
        CompletableFuture<LookupResult> cloudflareFuture = supplyCheck(getDnsProvider("cloudflare-security"), host);
        CompletableFuture<LookupResult> quad9Future = supplyCheck(getDnsProvider("quad9"), host);
        CompletableFuture<LookupResult> switchChFuture = supplyCheck(getDnsProvider("switch-ch"), host);

        // Local list checks
        CompletableFuture<LookupResult> phishDestroyFuture = CompletableFuture.supplyAsync(
                () -> LocalListUtil.isListed(Descriptor.PHISH_DESTROY, host)
                        ? LookupResult.PHISHING : LookupResult.ALLOWED,
                VIRTUAL_THREAD_EXECUTOR);
        CompletableFuture<LookupResult> phishingDatabaseFuture = CompletableFuture.supplyAsync(
                () -> LocalListUtil.isListed(Descriptor.PHISHING_DATABASE, host)
                        ? LookupResult.PHISHING : LookupResult.ALLOWED,
                VIRTUAL_THREAD_EXECUTOR);

        // Wait for all futures to complete
        try {
            CompletableFuture.allOf(
                    adGuardFuture,
                    cleanBrowsingFuture,
                    cloudflareFuture,
                    quad9Future,
                    switchChFuture,
                    phishDestroyFuture,
                    phishingDatabaseFuture
            ).orTimeout(5, TimeUnit.SECONDS).join();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
        }

        // Collect results
        Map<String, String> resultMap = new LinkedHashMap<>();
        resultMap.put("adGuardSecurity", safeGet(adGuardFuture, providerName, "adGuardSecurity").getValue());
        resultMap.put("cleanBrowsing", safeGet(cleanBrowsingFuture, providerName, "cleanBrowsingSecurity").getValue());
        resultMap.put("cloudflare", safeGet(cloudflareFuture, providerName, "cloudflareSecurity").getValue());
        resultMap.put("quad9", safeGet(quad9Future, providerName, "quad9").getValue());
        resultMap.put("switchCH", safeGet(switchChFuture, providerName, "switchCH").getValue());
        resultMap.put("phishDestroy", safeGet(phishDestroyFuture, providerName, "phishDestroy").getValue());
        resultMap.put("phishingDatabase", safeGet(phishingDatabaseFuture, providerName, "phishingDatabase").getValue());

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
     * @param provider      The provider configuration.
     * @param providerName  The provider display name for logging.
     * @param normalizedUrl The validated, normalized URL to lookup.
     * @return A {@link ResponseEntity} containing {@code {"result": "<value>"}},
     *         or an appropriate error response on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private static ResponseEntity<String> executeUpstream(@NonNull Provider provider,
                                                          @NonNull String providerName,
                                                          @NonNull String normalizedUrl) {
        Method method = provider.getMethod();
        ClassicRequestBuilder requestBuilder;
        String requestUrl = provider.buildRequestUrl(normalizedUrl);

        // Builds the request based on the provider's specified method (GET or POST)
        if (method == Method.GET) {
            requestBuilder = ClassicRequestBuilder.get(requestUrl);
        } else {
            Map<String, Object> requestBody = provider.buildBody(normalizedUrl);
            String jsonBody = "";

            // buildBody() returns null for GET providers;
            // POST providers (e.g. AlphaMountain) return a populated map.
            if (requestBody != null) {
                try {
                    jsonBody = JacksonUtil.MAPPER.writeValueAsString(requestBody);
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
            requestBuilder.addHeader(header.getKey(), header.getValue());
        }

        try {
            ClassicHttpRequest request = requestBuilder.build();

            return HTTP_CLIENT.execute(request, (ClassicHttpResponse response) -> {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                byte[] responseBytes = EntityUtils.toByteArray(entity, 10_000);

                // Rejects non-200 responses with provider-specific logging and error mapping
                if (statusCode != 200) {
                    if (statusCode == 400) {
                        log.warn("[{}] Upstream request failed with status code: 400 ({})", providerName, normalizedUrl);
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

                // Delegates response parsing and result mapping to the provider
                LookupResult result = provider.interpret(responseBytes, normalizedUrl);

                try {
                    String responseBody = JacksonUtil.MAPPER.writeValueAsString(
                            Map.of("result", result.getValue())
                    );
                    return ResponseEntity.ok()
                            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                            .body(responseBody);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.error("[{}] Failed to serialize result for '{}': {} ({})",
                            providerName, normalizedUrl, e.getMessage(), e.getClass().getName());
                    return ErrorUtil.RESP_502;
                }
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

    /**
     * Submits a DNS provider {@link AbstractDNSProvider#lookup} call as a
     * {@link CompletableFuture} on the virtual thread executor.
     *
     * @param provider The DNS provider to lookup with.
     * @param host     The hostname to lookup.
     * @return A {@link CompletableFuture} that resolves to the provider's {@link LookupResult}.
     */
    @SuppressWarnings("NestedMethodCall")
    private static @NonNull CompletableFuture<LookupResult> supplyCheck(@NonNull AbstractDNSProvider provider,
                                                                        @NonNull String host) {
        return CompletableFuture.supplyAsync(() -> provider.lookup(host), VIRTUAL_THREAD_EXECUTOR);
    }
}
