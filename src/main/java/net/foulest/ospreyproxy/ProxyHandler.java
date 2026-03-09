/*
 * OspreyProxy - backend code for our proxy server using Spring WebFlux.
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

import io.netty.channel.ChannelOption;
import io.netty.resolver.*;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Promise;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.providers.AlphaMountainProvider;
import net.foulest.ospreyproxy.providers.PrecisionSecProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.HashUtil;
import net.foulest.ospreyproxy.util.IPUtil;
import net.foulest.ospreyproxy.util.StressTestUtil;
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;
import tools.jackson.core.*;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.*;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Functional request handler for all proxy endpoints.
 */
@Slf4j
@Component
public class ProxyHandler {

    // Injected provider instances
    private final AlphaMountainProvider alphaMountainProvider;
    private final PrecisionSecProvider precisionSecProvider;

    // Maximum nesting depth enforced during upstream response validation
    private static final int MAX_NESTING_DEPTH = 50;

    // JSON mapper for parsing upstream responses and serializing error bodies
    private static final ObjectMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNumberLength(1000)
                            .maxNestingDepth(MAX_NESTING_DEPTH)
                            .maxStringLength(500_000)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .build())
            .build();

    // Pre-resolved JavaType for synchronous body deserialization
    private static final JavaType MAP_TYPE = MAPPER.constructType(
            new TypeReference<Map<String, String>>() {
            }
    );

    // Only allow these URI schemes
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    // Maximum allowed upstream response size in bytes (100 KB)
    private static final int MAX_RESPONSE_SIZE = 100_000;

    /**
     * Custom Netty DNS resolver that validates resolved IPs against private ranges
     * at connection time to prevent DNS rebinding attacks (TOCTOU).
     */
    private static final AddressResolverGroup<InetSocketAddress> SSRF_SAFE_RESOLVER = new AddressResolverGroup<>() {
        @Contract("_ -> new")
        @Override
        protected @NonNull AddressResolver<InetSocketAddress> newResolver(EventExecutor executor) {
            NameResolver<InetAddress> delegate = new DefaultNameResolver(executor);

            return new InetSocketAddressResolver(executor, new InetNameResolver(executor) {
                @Override
                protected void doResolve(String hostname, Promise<InetAddress> promise) {
                    delegate.resolve(hostname).addListener(future -> {
                        if (!future.isSuccess()) {
                            promise.setFailure(future.cause());
                            return;
                        }

                        InetAddress addr = (InetAddress) future.getNow();

                        if (IPUtil.isPrivateAddress(addr)) {
                            promise.setFailure(new UnknownHostException("Blocked: resolved to private address"));
                        } else {
                            promise.setSuccess(addr);
                        }
                    });
                }

                @Override
                protected void doResolveAll(String hostname, Promise<List<InetAddress>> promise) {
                    delegate.resolveAll(hostname).addListener(future -> {
                        if (!future.isSuccess()) {
                            promise.setFailure(future.cause());
                            return;
                        }

                        @SuppressWarnings("unchecked")
                        List<InetAddress> addrs = (List<InetAddress>) future.getNow();

                        for (InetAddress addr : addrs) {
                            if (IPUtil.isPrivateAddress(addr)) {
                                promise.setFailure(new UnknownHostException("Blocked: resolved to private address"));
                                return;
                            }
                        }

                        promise.setSuccess(addrs);
                    });
                }
            });
        }
    };

    // Bounded connection pool for the upstream WebClient to prevent resource exhaustion
    private static final ConnectionProvider CONNECTION_PROVIDER = ConnectionProvider.builder("upstream")
            .maxConnections(200)
            .pendingAcquireMaxCount(500)
            .maxIdleTime(Duration.ofSeconds(30))
            .maxLifeTime(Duration.ofMinutes(5))
            .build();

    // WebClient backed by Reactor Netty with SSRF-safe DNS, timeouts, no redirects
    private static final WebClient WEB_CLIENT = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(
                    HttpClient.create(CONNECTION_PROVIDER)
                            .resolver(SSRF_SAFE_RESOLVER)
                            .followRedirect(false)
                            .responseTimeout(Duration.ofSeconds(5))
                            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)))
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
        MAPPER.constructType(byte[].class);
    }

    // -------------------------------------------------------------------------
    // Handler methods (called by RouterConfig)
    // -------------------------------------------------------------------------

    /**
     * Handles POST /alphamountain requests.
     */
    @NonNull
    public Mono<ServerResponse> handleAlphaMountain(@NonNull ServerRequest request) {
        return proxyRequest(request, alphaMountainProvider);
    }

    /**
     * Handles POST /precisionsec requests.
     */
    @NonNull
    public Mono<ServerResponse> handlePrecisionSec(@NonNull ServerRequest request) {
        return proxyRequest(request, precisionSecProvider);
    }

    // -------------------------------------------------------------------------
    // Core proxy logic
    // -------------------------------------------------------------------------

    /**
     * Core method that implements the proxy logic for both providers. This method
     * performs IP extraction and rate limiting, request body parsing and validation,
     * URL normalization and security checks, and finally executes the upstream request.
     *
     * @param request The incoming ServerRequest from the client.
     * @param provider The provider configuration to use for this request (e.g., AlphaMountain).
     * @return A Mono emitting the ServerResponse to return to the client, which may be an error
     *         response or the proxied upstream response.
     */
    private Mono<ServerResponse> proxyRequest(@NonNull ServerRequest request,
                                              @NonNull Provider provider) {
        // ------------------------------------------------
        // IP Extraction and Rate Limiting
        // ------------------------------------------------

        // Resolve client IP from X-Real-IP header
        // NOTE: Make sure whatever VPS you use is behind Cloudflare, Nginx, and a solid firewall!
        // Prevent all direct connections entirely except for Cloudflare's IP ranges, and ensure the
        // X-Real-IP header is set correctly by your reverse proxy. Otherwise, an attacker could bypass
        // rate limits and blocks by connecting directly with spoofed IPs. Not good!
        String realIp = request.headers().firstHeader("X-Real-IP");

        // Fallback to remote address if X-Real-IP is missing or empty
        if (realIp == null || realIp.isBlank()) {
            InetSocketAddress remote = request.remoteAddress().orElse(null);
            realIp = remote != null ? remote.getAddress().getHostAddress() : "unknown";
        }

        String providerName = provider.getName();

        // Log a warning if we couldn't determine the client's IP address
        if (realIp.equals("unknown")) {
            log.warn("{} Could not determine client IP address; applying rate limits to 'unknown' IP", providerName);
        }

        // Hash the IP for rate limiting, or use a synthetic IP in stress test mode
        String hashedIp = StressTestUtil.isEnabled()
                ? StressTestUtil.syntheticIp()
                : HashUtil.hashIp(realIp);

        // Checks if the IP is burst-blocked (consumes one token)
        if (isBurstBlocked(provider, hashedIp, providerName)) {
            return ErrorUtil.resp429();
        }

        // Checks if the IP is sustained-blocked (consumes one token)
        if (isSustainedBlocked(provider, hashedIp, providerName)) {
            return ErrorUtil.resp429();
        }

        // Checks if the IP is invalid-request-blocked (doesn't consume token, only checks block)
        // The asymmetry here is intentional: invalid requests can only be determined after parsing the body,
        // so we don't want to consume a token on every request upfront. Instead, we check for an active block first,
        // and only consume a token when we actually identify an invalid request.
        if (provider.isInvalidRequestBlocked(hashedIp)) {
            log.warn("[{}] Invalid request block duration active for IP", providerName);
            return ErrorUtil.resp429();
        }

        // ------------------------------------------------
        // Request Body Parsing and Validation
        // ------------------------------------------------

        // Read body as raw bytes, then deserialize with the synchronous Jackson parser
        return request.bodyToMono(byte[].class).defaultIfEmpty(new byte[0]).flatMap(bytes -> {
            Map<String, String> incoming;

            // Rejects empty bodies
            if (bytes.length == 0) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with empty body", ErrorUtil.resp400());
            }

            // Parse the request body as JSON
            try {
                incoming = MAPPER.readValue(bytes, MAP_TYPE);
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with malformed JSON body", ErrorUtil.resp400());
            }

            // Rejects a null parse result (e.g., body was the JSON literal "null")
            if (incoming == null) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with null JSON body", ErrorUtil.resp400());
            }

            // Rejects unexpected fields
            if (incoming.size() > 1) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with unexpected fields", ErrorUtil.resp400());
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
                                    "Blocked request with non-string url value", ErrorUtil.resp400());
                        }
                        break;
                    }
                }
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with malformed JSON body", ErrorUtil.resp400());
            }

            // ------------------------------------------------
            // URL Normalization and Validation
            // ------------------------------------------------

            String rawUrl = incoming.getOrDefault("url", "");
            String url = rawUrl != null ? rawUrl.trim() : "";

            // Rejects missing or empty URLs
            if (url.isEmpty()) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with missing or empty URL", ErrorUtil.resp400());
            }

            // Rejects excessively long URLs
            if (url.length() > 8192) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with excessively long URL", ErrorUtil.resp400());
            }

            URI parsedUri;

            // Normalizes and validates URL syntax
            try {
                parsedUri = new URI(url).normalize();
            } catch (URISyntaxException | IllegalArgumentException e) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with malformed URL", ErrorUtil.resp400());
            }

            String scheme = parsedUri.getScheme();

            // Prepends https:// for schemeless URLs (e.g., example.com)
            if (scheme == null) {
                try {
                    parsedUri = new URI("https://" + parsedUri).normalize();
                    parsedUri.toURL();
                    scheme = parsedUri.getScheme();
                } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
                    return rejectInvalidRequest(provider, hashedIp, providerName,
                            "Blocked request with malformed schemeless URL", ErrorUtil.resp400());
                }
            }

            scheme = scheme.toLowerCase(Locale.ROOT);

            // Rejects unsupported schemes (only http and https allowed)
            if (!ALLOWED_SCHEMES.contains(scheme)) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with disallowed URL scheme", ErrorUtil.resp400());
            }

            String host = parsedUri.getHost();

            // Extracts host from authority if getHost() is null
            if (host == null || host.isBlank()) {
                String authority = parsedUri.getRawAuthority();

                if (authority == null) {
                    return rejectInvalidRequest(provider, hashedIp, providerName,
                            "Blocked request with no host", ErrorUtil.resp400());
                }

                // Handle bracketed IPv6 literals (e.g., [::1] or [::1]:8080)
                if (!authority.isEmpty() && authority.charAt(0) == '[') {
                    int closingBracket = authority.indexOf(']');

                    if (closingBracket < 0) {
                        return rejectInvalidRequest(provider, hashedIp, providerName,
                                "Blocked request with malformed IPv6 host", ErrorUtil.resp400());
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
                        "Blocked request with empty host", ErrorUtil.resp400());
            }

            host = host.toLowerCase(Locale.ROOT);

            // Strips userinfo from URL to prevent URL parsing differentials (e.g., https://paypal.com@evil.com)
            // The userinfo component is not relevant to threat scanning; only the host matters
            if (parsedUri.getUserInfo() != null) {
                try {
                    int port = parsedUri.getPort();
                    String path = parsedUri.getPath();
                    String query = parsedUri.getQuery();
                    String fragment = parsedUri.getFragment();
                    parsedUri = new URI(scheme, null, host, port, path, query, fragment);
                } catch (URISyntaxException e) {
                    return rejectInvalidRequest(provider, hashedIp, providerName,
                            "Blocked request with unstrippable userinfo in URL", ErrorUtil.resp400());
                }
            }

            // Blocks private/internal hosts
            if (IPUtil.isPrivateHost(host, providerName)) {
                return rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request to private/internal host", ErrorUtil.resp400());
            }

            // ------------------------------------------------
            // Upstream Request Execution
            // ------------------------------------------------

            // Skips upstream call and returns fake response for stress tests
            if (StressTestUtil.isEnabled()) {
                return ErrorUtil.resp200();
            }

            // Sends the normalized URL string to the upstream provider
            String normalizedUrl = parsedUri.toString();
            return executeUpstream(provider, normalizedUrl);
        }).onErrorResume(Exception.class, e -> rejectInvalidRequest(provider, hashedIp, providerName,
                "Blocked request with unreadable body", ErrorUtil.resp400())
        );
    }

    /**
     * Executes the upstream request to the provider with the normalized URL.
     *
     * @param provider The provider configuration to use for this request.
     * @param normalizedUrl The validated and normalized URL to check.
     * @return A Mono emitting the ServerResponse to return to the client.
     */
    @SuppressWarnings("NestedAssignment")
    private static @NonNull Mono<ServerResponse> executeUpstream(@NonNull Provider provider,
                                                                 @NonNull String normalizedUrl) {
        String method = provider.getMethod();
        String uri = provider.buildRequestUrl(normalizedUrl);
        WebClient.RequestHeadersSpec<?> requestSpec;

        // Builds the request spec based on the provider's method and body configuration
        if (method.equals("GET")) {
            requestSpec = WEB_CLIENT.get().uri(uri);
        } else {
            Map<String, Object> requestBody = provider.buildBody(normalizedUrl);
            WebClient.RequestBodySpec postSpec = WEB_CLIENT.post()
                    .uri(uri)
                    .contentType(MediaType.APPLICATION_JSON);
            requestSpec = requestBody != null ? postSpec.bodyValue(requestBody) : postSpec;
        }

        // Applies provider-specific headers (e.g., API key headers)
        for (Map.Entry<String, String> header : provider.getHeaders().entrySet()) {
            requestSpec = requestSpec.header(header.getKey(), header.getValue());
        }

        String providerName = provider.getName();

        // Retrieves the response body as bytes to enforce size limits before parsing
        return requestSpec.retrieve().bodyToMono(byte[].class).flatMap(bytes -> {
                    if (bytes.length == 0) {
                        log.warn("[{}] Upstream response was empty", providerName);
                        return ErrorUtil.resp502();
                    }

                    if (bytes.length > MAX_RESPONSE_SIZE) {
                        log.warn("[{}] Upstream response exceeded maximum size: {} bytes", providerName, bytes.length);
                        return ErrorUtil.resp502();
                    }

                    // Validate that the response is well-formed JSON using a streaming parser.
                    // Manually tracks nesting depth as defense-in-depth against CVE-2026-29062
                    // (nesting depth bypass in certain Jackson parser implementations).
                    try (JsonParser parser = MAPPER.createParser(bytes)) {
                        int depth = 0;
                        JsonToken token;

                        while ((token = parser.nextToken()) != null) {
                            if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                                depth++;

                                if (depth > MAX_NESTING_DEPTH) {
                                    log.warn("[{}] Upstream response exceeded maximum nesting depth: {}", providerName, depth);
                                    return ErrorUtil.resp502();
                                }
                            } else if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                                depth--;
                            }
                        }
                    } catch (JacksonException e) {
                        log.warn("[{}] Failed to parse upstream response as JSON", providerName, e);
                        return ErrorUtil.resp502();
                    }

                    // Pass through the validated raw bytes directly
                    return ServerResponse.ok()
                            .contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(bytes);
                })
                .onErrorResume(WebClientResponseException.class, e -> {
                    int statusCode = e.getStatusCode().value();
                    log.warn("[{}] Upstream request failed with status code: {}", providerName, statusCode);

                    return switch (statusCode) {
                        case 400 -> ErrorUtil.resp400();
                        case 404 -> ErrorUtil.resp404();
                        case 415 -> ErrorUtil.resp415();
                        case 429 -> ErrorUtil.resp429();
                        default -> ErrorUtil.resp502();
                    };
                })
                .onErrorResume(Exception.class, e -> {
                    log.error("[{}] Unexpected error during upstream request", providerName, e);
                    return ErrorUtil.resp502();
                });
    }

    /**
     * Checks if the given IP is currently burst-blocked or has exceeded the burst rate limit,
     * consuming one token from the burst bucket. If the IP is burst-blocked, logs a warning and returns true.
     * If the IP has exceeded the burst rate limit, logs a warning, applies the burst block, and returns true.
     * Otherwise, returns false to allow the request to proceed.
     *
     * @param provider The provider to check the burst block and bucket for.
     * @param hashedIp The hashed IP address to check and consume from the burst bucket.
     * @param providerName The provider name for logging purposes.
     * @return A boolean indicating whether the IP is currently burst-blocked or has exceeded the burst rate limit
     *         (true if blocked, false if allowed).
     */
    private static boolean isBurstBlocked(@NonNull Provider provider,
                                          @NonNull String hashedIp,
                                          @NonNull String providerName) {
        if (provider.isBurstBlocked(hashedIp)) {
            log.warn("[{}] Burst block duration active for IP", providerName);
            return true;
        }

        if (!provider.getBurstBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] Burst rate limit exceeded for IP", providerName);
            provider.blockBurst(hashedIp);
            return true;
        }
        return false;
    }

    /**
     * Checks if the given IP is currently sustained-blocked or has exceeded the sustained rate limit,
     * consuming one token from the sustained bucket. If the IP is sustained-blocked, logs a warning and returns true.
     * If the IP has exceeded the sustained rate limit, logs a warning, applies the sustained block, and returns true.
     * Otherwise, returns false to allow the request to proceed.
     *
     * @param provider The provider to check the sustained block and bucket for.
     * @param hashedIp The hashed IP address to check and consume from the sustained bucket.
     * @param providerName The provider name for logging purposes.
     * @return A boolean indicating whether the IP is currently sustained-blocked or has exceeded the sustained
     *         rate limit (true if blocked, false if allowed).
     */
    private static boolean isSustainedBlocked(@NonNull Provider provider,
                                              @NonNull String hashedIp,
                                              @NonNull String providerName) {
        if (provider.isSustainedBlocked(hashedIp)) {
            log.warn("[{}] Sustained block duration active for IP", providerName);
            return true;
        }

        if (!provider.getSustainedBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] Sustained rate limit exceeded for IP", providerName);
            provider.blockSustained(hashedIp);
            return true;
        }
        return false;
    }

    /**
     * Consumes one token from the invalid request bucket for the given IP, blocking it
     * if the bucket is exhausted. Logs the provided message and returns the given error
     * response if the IP is not (yet) blocked. Returns a 429 response if it is blocked.
     *
     * @param provider The provider to consume the invalid request token from.
     * @param hashedIp The hashed IP address to check and consume from.
     * @param providerName The provider name for logging purposes.
     * @param logMessage The warning message to log when the request is rejected.
     * @param errorResponse The error response to return when the request is rejected normally.
     * @return A Mono emitting the appropriate ServerResponse.
     */
    private static @NonNull Mono<ServerResponse> rejectInvalidRequest(@NonNull Provider provider,
                                                                      @NonNull String hashedIp,
                                                                      @NonNull String providerName,
                                                                      @NonNull String logMessage,
                                                                      @NonNull Mono<ServerResponse> errorResponse) {
        // Consumes a token from the invalid request bucket, blocking the IP if the bucket is exhausted
        if (!provider.getInvalidRequestBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] Invalid request rate limit exceeded for IP", providerName);
            provider.blockInvalidRequest(hashedIp);
            return ErrorUtil.resp429();
        }

        // If the IP is not yet blocked, log the reason and return the provided error response
        log.warn("[{}] {}", providerName, logMessage);
        return errorResponse;
    }
}
