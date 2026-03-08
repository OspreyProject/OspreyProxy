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
import net.foulest.ospreyproxy.providers.AlphaMountainProvider;
import net.foulest.ospreyproxy.providers.PrecisionSecProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.util.BucketUtil;
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
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.type.TypeReference;
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
@Component
public class ProxyHandler {

    // Injected provider instances
    private final AlphaMountainProvider alphaMountainProvider;
    private final PrecisionSecProvider precisionSecProvider;

    // Jackson type reference for synchronous body deserialization (Map<String, String>)
    private static final TypeReference<Map<String, String>> MAP_TYPE = new TypeReference<>() {
    };

    // Maximum nesting depth enforced during upstream response validation.
    // Mirrors the StreamReadConstraints limit above; applied manually during
    // the streaming token-walk to catch any parser that fails to enforce it.
    private static final int MAX_NESTING_DEPTH = 50;

    // JSON mapper for parsing upstream responses and serializing error bodies.
    // Explicit StreamReadConstraints harden against CVE GHSA-72hv-8253-57qq
    // (async parser maxNumberLength bypass) and CVE-2026-29062 (nesting depth
    // bypass in UTF8DataInputJsonParser / ReaderBasedJsonParser) at the
    // application level, regardless of which internal parser Jackson selects.
    private static final ObjectMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNumberLength(1000)
                            .maxNestingDepth(MAX_NESTING_DEPTH)
                            .maxStringLength(500_000)
                            .build())
                    .build())
            .build();

    // Only allow these URI schemes
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    // Maximum allowed upstream response size in bytes (100 KB)
    private static final int MAX_RESPONSE_SIZE = 100_000;

    // Pre-built JSON error bodies (serialized once at class load)
    private static final String BODY_400_UNEXPECTED = jsonError("Unexpected fields in request");
    private static final String BODY_400_MISSING_URL = jsonError("Missing or empty 'url' field");
    private static final String BODY_400_URL_TOO_LONG = jsonError("URL too long");
    private static final String BODY_400_MALFORMED = jsonError("Malformed URL");
    private static final String BODY_400_SCHEME = jsonError("URL scheme not allowed");
    private static final String BODY_400_NOT_ALLOWED = jsonError("URL not allowed");
    private static final String BODY_429_BURST = jsonError("Per-IP burst rate limit exceeded");
    private static final String BODY_429_SUSTAINED = jsonError("Per-IP sustained rate limit exceeded");
    private static final String BODY_502_FAILED = jsonError("Upstream request failed");
    private static final String BODY_502_TOO_LARGE = jsonError("Upstream response too large");
    private static final String BODY_502_INVALID_JSON = jsonError("Invalid JSON in upstream response");
    private static final String BODY_404 = jsonError("Not found");

    // Pre-built stress test response body
    private static final String BODY_STRESS_TEST = StressTestUtil.getFakeResponse();

    // Pre-cached Mono<ServerResponse> instances for all error and fast-path responses
    private static final Mono<ServerResponse> RESP_400_UNEXPECTED = buildResponse(400, BODY_400_UNEXPECTED);
    private static final Mono<ServerResponse> RESP_400_MISSING_URL = buildResponse(400, BODY_400_MISSING_URL);
    private static final Mono<ServerResponse> RESP_400_URL_TOO_LONG = buildResponse(400, BODY_400_URL_TOO_LONG);
    private static final Mono<ServerResponse> RESP_400_MALFORMED = buildResponse(400, BODY_400_MALFORMED);
    private static final Mono<ServerResponse> RESP_400_SCHEME = buildResponse(400, BODY_400_SCHEME);
    private static final Mono<ServerResponse> RESP_400_NOT_ALLOWED = buildResponse(400, BODY_400_NOT_ALLOWED);
    private static final Mono<ServerResponse> RESP_429_BURST = buildResponse(429, BODY_429_BURST);
    private static final Mono<ServerResponse> RESP_429_SUSTAINED = buildResponse(429, BODY_429_SUSTAINED);
    private static final Mono<ServerResponse> RESP_502_FAILED = buildResponse(502, BODY_502_FAILED);
    private static final Mono<ServerResponse> RESP_502_TOO_LARGE = buildResponse(502, BODY_502_TOO_LARGE);
    private static final Mono<ServerResponse> RESP_502_INVALID_JSON = buildResponse(502, BODY_502_INVALID_JSON);
    public static final Mono<ServerResponse> RESP_404 = buildResponse(404, BODY_404);
    private static final Mono<ServerResponse> RESP_STRESS_TEST = buildResponse(200, BODY_STRESS_TEST);

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
        // Resolve client IP from X-Real-IP header
        String realIp = request.headers().firstHeader("X-Real-IP");

        // Fallback to remote address if X-Real-IP is missing or empty
        if (realIp == null || realIp.isBlank()) {
            InetSocketAddress remote = request.remoteAddress().orElse(null);
            realIp = remote != null ? remote.getAddress().getHostAddress() : "unknown";
        }

        // Hash the IP for rate limiting, or use a synthetic IP in stress test mode
        String hashedIp = StressTestUtil.isEnabled()
                ? StressTestUtil.syntheticIp()
                : HashUtil.hashIp(realIp);

        // Per-IP burst rate limit
        if (!BucketUtil.getBurstBucket(hashedIp).tryConsume(1)) {
            return RESP_429_BURST;
        }

        // Per-IP sustained rate limit
        if (!BucketUtil.getSustainedBucket(hashedIp).tryConsume(1)) {
            return RESP_429_SUSTAINED;
        }

        // Read body as raw bytes, then deserialize with the synchronous Jackson parser.
        // Spring WebFlux's default bodyToMono(MAP_TYPE_REF) uses the non-blocking (async)
        // JSON parser, which bypasses maxNumberLength validation (CVE GHSA-72hv-8253-57qq).
        // By parsing raw bytes with MAPPER.readValue() we use the synchronous parser,
        // which correctly enforces StreamReadConstraints (maxNumberLength, maxNestingDepth, etc.).
        return request.bodyToMono(byte[].class).flatMap(bytes -> {
            Map<String, String> incoming;

            try {
                incoming = MAPPER.readValue(bytes, MAP_TYPE);
            } catch (JacksonException e) {
                return RESP_400_MALFORMED;
            }

            // Rejects unexpected fields
            if (incoming.size() > 1) {
                return RESP_400_UNEXPECTED;
            }

            String url = incoming.getOrDefault("url", "").trim();

            // Rejects missing or empty URLs
            if (url.isEmpty()) {
                return RESP_400_MISSING_URL;
            }

            // Rejects excessively long URLs
            if (url.length() > 2048) {
                return RESP_400_URL_TOO_LONG;
            }

            URI parsedUri;

            // Normalizes and validates URL syntax
            try {
                parsedUri = new URI(url).normalize();
            } catch (URISyntaxException | IllegalArgumentException e) {
                return RESP_400_MALFORMED;
            }

            String scheme = parsedUri.getScheme();

            // Prepends https:// for schemeless URLs (e.g., example.com)
            if (scheme == null) {
                try {
                    parsedUri = new URI("https://" + url).normalize();
                    parsedUri.toURL();
                    scheme = parsedUri.getScheme();
                } catch (MalformedURLException | URISyntaxException | IllegalArgumentException e) {
                    return RESP_400_MALFORMED;
                }
            }

            // Rejects unsupported schemes (only http and https allowed)
            // noinspection NestedMethodCall
            if (!ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
                return RESP_400_SCHEME;
            }

            String host = parsedUri.getHost();

            // Extracts host from authority if getHost() is null
            if (host == null) {
                String authority = parsedUri.getRawAuthority();

                if (authority == null) {
                    return RESP_400_MALFORMED;
                }

                int endIndex = authority.lastIndexOf(':');
                host = authority.contains(":") ? authority.substring(0, endIndex) : authority;
            }

            // Rejects empty hosts
            if (host.isBlank()) {
                return RESP_400_MALFORMED;
            }

            host = host.toLowerCase(Locale.ROOT);

            // Blocks userinfo to prevent URL parsing differentials
            if (parsedUri.getUserInfo() != null) {
                return RESP_400_NOT_ALLOWED;
            }

            // Blocks private/internal hosts
            if (IPUtil.isPrivateHost(host)) {
                return RESP_400_NOT_ALLOWED;
            }

            String normalizedUrl = parsedUri.toString();

            // Skips upstream call and returns fake response for stress tests
            if (StressTestUtil.isEnabled()) {
                return RESP_STRESS_TEST;
            }
            return executeUpstream(provider, normalizedUrl);
        });
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

        // Retrieves the response body as bytes to enforce size limits before parsing
        return requestSpec.retrieve().bodyToMono(byte[].class).flatMap(bytes -> {
                    if (bytes.length == 0) {
                        return RESP_502_INVALID_JSON;
                    }

                    if (bytes.length > MAX_RESPONSE_SIZE) {
                        return RESP_502_TOO_LARGE;
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
                                    return RESP_502_INVALID_JSON;
                                }
                            } else if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                                depth--;
                            }
                        }
                    } catch (JacksonException e) {
                        return RESP_502_INVALID_JSON;
                    }

                    // Pass through the validated raw bytes directly
                    return ServerResponse.ok()
                            .contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(bytes);
                })
                .onErrorResume(WebClientResponseException.class, e -> RESP_502_FAILED)
                .onErrorResume(Exception.class, e -> RESP_502_FAILED);
    }

    // -------------------------------------------------------------------------
    // Helper methods
    // -------------------------------------------------------------------------

    /**
     * Serializes an error message to JSON.
     */
    private static @NonNull String jsonError(@NonNull String message) {
        try {
            return MAPPER.writeValueAsString(Map.of("error", message));
        } catch (JacksonException e) {
            return "{\"error\": \"Internal server error\"}";
        }
    }

    /**
     * Builds a cached Mono&lt;ServerResponse&gt; with the given status and body.
     * The .cache() ensures the ServerResponse is built once and reused.
     *
     * @param status The HTTP status code for the response.
     * @param body The JSON body string for the response.
     * @return A cached Mono emitting the ServerResponse with the specified status and body.
     */
    private static @NonNull Mono<ServerResponse> buildResponse(int status, @NonNull String body) {
        return ServerResponse.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .cache();
    }
}
