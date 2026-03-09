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
package net.foulest.ospreyproxy.config;

import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.ErrorUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Global security configuration for the proxy server.
 */
@Slf4j
@Configuration
public class SecurityConfig implements WebFluxConfigurer {

    // Path exempted from Content-Type enforcement (read-only GET, no request body)
    private static final String PRIVACY_PATH = "/privacy";

    // Maximum allowed body size for incoming requests (10 KB).
    // Applied to the server-side codec via configureHttpMessageCodecs() so that
    // ServerRequest.bodyToMono() enforces this limit, and to the Content-Length
    // pre-check in securityFilter() to reject oversized requests before buffering.
    private static final int MAX_BODY_SIZE = 10_240;

    // HTTP methods that typically carry no request body; exempt from Content-Type enforcement.
    // DELETE is included because this proxy has no endpoints that accept DELETE with a body;
    // per RFC 9110, a body on DELETE has no defined semantics and is ignored by this server.
    private static final Set<HttpMethod> BODYLESS_METHODS = Set.of(
            HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS, HttpMethod.DELETE
    );

    /**
     * Applies the server-side codec body size limit programmatically.
     * <p>
     * {@code spring.codec.max-in-memory-size} only configures the WebClient and response
     * decoding codecs; it does NOT apply to {@code ServerRequest.bodyToMono()} used here.
     * This override ensures the same 10 KB limit is enforced on incoming request bodies,
     * causing {@link DataBufferLimitException} at 10 KB instead of Spring's default 256 KB.
     */
    @Override
    public void configureHttpMessageCodecs(@NonNull ServerCodecConfigurer configurer) {
        configurer.defaultCodecs().maxInMemorySize(MAX_BODY_SIZE);
    }

    /**
     * Global exception handler that intercepts {@link DataBufferLimitException} thrown when an
     * incoming request body exceeds {@link #MAX_BODY_SIZE}. Without this, Spring's default error
     * handler produces a 500; this handler returns a clean 400 instead.
     * <p>
     * Acts as a safety net for chunked transfer requests that omit Content-Length (so the
     * filter pre-check cannot reject early). Runs at {@code @Order(-2)}, just above Spring's
     * built-in {@code DefaultErrorWebExceptionHandler} at {@code @Order(-1)}.
     */
    @Bean
    @Order(-2)
    public WebExceptionHandler bufferLimitExceptionHandler() {
        return (ServerWebExchange exchange, Throwable ex) -> {
            if (!(ex instanceof DataBufferLimitException)) {
                return Mono.error(ex);
            }

            log.warn("Request body exceeded buffer limit: {}", ex.getMessage());
            ServerHttpResponse response = exchange.getResponse();

            if (response.isCommitted()) {
                return Mono.error(ex);
            }

            response.setStatusCode(HttpStatus.BAD_REQUEST);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(ErrorUtil.BYTES_400)));
        };
    }

    /**
     * Global security filter that applies to all requests. Sets security headers on every response
     * and enforces that incoming requests have a Content-Type of application/json, rejecting with
     * 415 Unsupported Media Type if not. The /privacy endpoint is exempt since it is a GET with
     * no request body. Runs first (order 1) to ensure security headers are always set even on
     * rejected requests.
     * <p>
     * Also rejects requests whose declared Content-Length exceeds {@link #MAX_BODY_SIZE}
     * before any body bytes are buffered, as an early-exit optimization for well-behaved clients.
     */
    @Bean
    @Order(1)
    public WebFilter securityFilter() {
        return (ServerWebExchange exchange, WebFilterChain chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();
            HttpHeaders responseHeaders = response.getHeaders();

            // Default response content type
            responseHeaders.setContentType(MediaType.APPLICATION_JSON);

            // Security headers on every response
            responseHeaders.set("X-Content-Type-Options", "nosniff");
            responseHeaders.set("X-Frame-Options", "DENY");
            responseHeaders.set("Content-Security-Policy", "default-src 'none'");
            responseHeaders.set("Referrer-Policy", "no-referrer");
            responseHeaders.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
            responseHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            String path = request.getPath().value();
            HttpMethod method = request.getMethod();

            // Skip Content-Type and size checks for bodyless HTTP methods and the privacy endpoint
            if (BODYLESS_METHODS.contains(method)
                    || path.equals(PRIVACY_PATH)
                    || path.startsWith(PRIVACY_PATH + "/")) {
                return chain.filter(exchange);
            }

            // Early rejection for requests declaring an oversized Content-Length.
            // getContentLength() returns -1 when the header is absent (chunked transfer),
            // in which case the codec limit and WebExceptionHandler handle it instead.
            long contentLength = request.getHeaders().getContentLength();

            if (contentLength > MAX_BODY_SIZE) {
                log.warn("Rejected request with oversized Content-Length: {} bytes", contentLength);
                response.setStatusCode(HttpStatus.BAD_REQUEST);
                return response.writeWith(Mono.just(response.bufferFactory().wrap(ErrorUtil.BYTES_400)));
            }

            // Fast-path: compare raw header string before allocating a MediaType object.
            // The vast majority of valid clients send exactly "application/json"; only
            // fall back to full MIME parsing for values with parameters (e.g., charset).
            String rawContentType = request.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);

            boolean valid = rawContentType != null
                    && (rawContentType.equals("application/json")
                    || (rawContentType.startsWith("application/json")
                    && MediaType.parseMediaType(rawContentType).equalsTypeAndSubtype(MediaType.APPLICATION_JSON)));

            if (!valid) {
                response.setStatusCode(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
                return response.writeWith(Mono.just(response.bufferFactory().wrap(ErrorUtil.BYTES_415)));
            }
            return chain.filter(exchange);
        };
    }
}
