package net.foulest.ospreyproxy.config;

import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

@Configuration
public class SecurityConfig {

    // Error messages
    private static final String CONTENT_TYPE_ERROR = "{\"error\": \"Content-Type must be application/json\"}";
    private static final String BODY_TOO_LARGE_ERROR = "{\"error\": \"Request body too large\"}";

    // Pre-allocated error response byte arrays to avoid repeated getBytes() allocation
    private static final byte[] CONTENT_TYPE_ERROR_BYTES = CONTENT_TYPE_ERROR.getBytes(StandardCharsets.UTF_8);
    private static final byte[] BODY_TOO_LARGE_ERROR_BYTES = BODY_TOO_LARGE_ERROR.getBytes(StandardCharsets.UTF_8);

    // Maximum request body size in bytes (10 KB)
    private static final int MAX_BODY_SIZE = 10_240;

    // Singleton exception to avoid stack trace generation on every oversized request
    private static final RequestBodyTooLargeException BODY_TOO_LARGE = new RequestBodyTooLargeException();

    /**
     * Global security filter that applies to all requests. Sets security headers on every response
     * and enforces that incoming requests have a Content-Type of application/json, rejecting with
     * 415 Unsupported Media Type if not. Runs first (order 1) to ensure security headers are always
     * set even on rejected requests.
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
            responseHeaders.set("X-XSS-Protection", "1; mode=block");
            responseHeaders.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
            responseHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            MediaType contentType = request.getHeaders().getContentType();

            // Reject requests without application/json Content-Type
            if (contentType == null || !contentType.equalsTypeAndSubtype(MediaType.APPLICATION_JSON)) {
                response.setStatusCode(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
                return response.writeWith(Mono.just(response.bufferFactory().wrap(CONTENT_TYPE_ERROR_BYTES)));
            }
            return chain.filter(exchange);
        };
    }

    /**
     * Enforces a hard body-size limit on all incoming requests.
     * Decorates the request body Flux to count bytes as they arrive and
     * cancel with an error signal if the limit is exceeded. The decorated
     * request is passed downstream so Spring can still read the body normally.
     * Runs second (order 2).
     */
    @Bean
    @Order(2)
    public WebFilter bodySizeFilter() {
        return (ServerWebExchange exchange, WebFilterChain chain) -> {
            AtomicInteger bytesRead = new AtomicInteger(0);
            ServerHttpResponse response = exchange.getResponse();

            // Decorate the request body flux with a byte counter
            ServerHttpRequestDecorator decorator = new ServerHttpRequestDecorator(exchange.getRequest()) {
                @Override
                public @NonNull Flux<DataBuffer> getBody() {
                    return super.getBody().handle((dataBuffer, sink) -> {
                        int count = dataBuffer.readableByteCount();

                        if (bytesRead.addAndGet(count) > MAX_BODY_SIZE) {
                            DataBufferUtils.release(dataBuffer);
                            sink.error(BODY_TOO_LARGE);
                        } else {
                            sink.next(dataBuffer);
                        }
                    });
                }
            };

            return chain.filter(exchange.mutate().request(decorator).build())
                    .onErrorResume(RequestBodyTooLargeException.class, e -> {
                        response.setStatusCode(HttpStatus.CONTENT_TOO_LARGE);
                        return response.writeWith(Mono.just(response.bufferFactory().wrap(BODY_TOO_LARGE_ERROR_BYTES)));
                    });
        };
    }

    /**
     * Sentinel exception used to signal body size exceeded within the reactive pipeline.
     */
    private static class RequestBodyTooLargeException extends RuntimeException {

        RequestBodyTooLargeException() {
            super("Request body too large", null, true, false);
        }
    }
}
