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

import net.foulest.ospreyproxy.util.ErrorUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Global security configuration for the proxy server.
 */
@Configuration
public class SecurityConfig {

    // Path exempted from Content-Type enforcement (read-only GET, no request body)
    private static final String PRIVACY_PATH = "/privacy";

    // HTTP methods that typically carry no request body; exempt from Content-Type enforcement.
    // DELETE is included because this proxy has no endpoints that accept DELETE with a body;
    // per RFC 9110, a body on DELETE has no defined semantics and is ignored by this server.
    private static final Set<HttpMethod> BODYLESS_METHODS = Set.of(
            HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS, HttpMethod.DELETE
    );

    /**
     * Global security filter that applies to all requests. Sets security headers on every response
     * and enforces that incoming requests have a Content-Type of application/json, rejecting with
     * 415 Unsupported Media Type if not. The /privacy endpoint is exempt since it is a GET with
     * no request body. Runs first (order 1) to ensure security headers are always set even on
     * rejected requests.
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

            // Skip Content-Type check for bodyless HTTP methods and the privacy endpoint
            if (BODYLESS_METHODS.contains(method)
                    || path.equals(PRIVACY_PATH)
                    || path.startsWith(PRIVACY_PATH + "/")) {
                return chain.filter(exchange);
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
                return response.writeWith(Mono.just(response.bufferFactory().wrap(ErrorUtil.BYTES_415_CONTENT_TYPE)));
            }
            return chain.filter(exchange);
        };
    }
}
