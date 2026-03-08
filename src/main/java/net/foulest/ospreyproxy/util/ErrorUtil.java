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
package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Central store for all pre-serialized JSON error responses.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ErrorUtil {

    // 200 OK
    private static final byte[] BYTES_200_OK = bytes("OK");

    // 400 Bad Request
    private static final byte[] BYTES_400_UNEXPECTED = bytes("Unexpected fields in request");
    private static final byte[] BYTES_400_MISSING_URL = bytes("Missing or empty 'url' field");
    private static final byte[] BYTES_400_URL_TOO_LONG = bytes("URL too long");
    private static final byte[] BYTES_400_MALFORMED = bytes("Malformed URL");
    private static final byte[] BYTES_400_SCHEME = bytes("URL scheme not allowed");
    private static final byte[] BYTES_400_NOT_ALLOWED = bytes("URL not allowed");
    private static final byte[] BYTES_400_PROVIDER = bytes("Rejected by provider");

    // 415 Unsupported Media Type
    public static final byte[] BYTES_415_CONTENT_TYPE = bytes("Content-Type must be application/json");
    private static final byte[] BYTES_415_PROVIDER = bytes("Provider does not accept this Content-Type");

    // 429 Too Many Requests
    private static final byte[] BYTES_429_BURST = bytes("Per-IP burst rate limit exceeded");
    private static final byte[] BYTES_429_SUSTAINED = bytes("Per-IP sustained rate limit exceeded");
    private static final byte[] BYTES_429_PROVIDER = bytes("Provider rate limit exceeded");

    // 404 Not Found
    private static final byte[] BYTES_404 = bytes("Not found");
    private static final byte[] BYTES_404_PROVIDER = bytes("Provider endpoint not found");

    // 502 Bad Gateway
    private static final byte[] BYTES_502_FAILED = bytes("Upstream request failed");
    private static final byte[] BYTES_502_TOO_LARGE = bytes("Upstream response too large");
    private static final byte[] BYTES_502_INVALID_JSON = bytes("Invalid JSON in upstream response");

    public static @NonNull Mono<ServerResponse> resp200OK() {
        return build(200, BYTES_200_OK);
    }

    public static @NonNull Mono<ServerResponse> resp400Unexpected() {
        return build(400, BYTES_400_UNEXPECTED);
    }

    public static @NonNull Mono<ServerResponse> resp400MissingUrl() {
        return build(400, BYTES_400_MISSING_URL);
    }

    public static @NonNull Mono<ServerResponse> resp400UrlTooLong() {
        return build(400, BYTES_400_URL_TOO_LONG);
    }

    public static @NonNull Mono<ServerResponse> resp400Malformed() {
        return build(400, BYTES_400_MALFORMED);
    }

    public static @NonNull Mono<ServerResponse> resp400Scheme() {
        return build(400, BYTES_400_SCHEME);
    }

    public static @NonNull Mono<ServerResponse> resp400NotAllowed() {
        return build(400, BYTES_400_NOT_ALLOWED);
    }

    public static @NonNull Mono<ServerResponse> resp400Provider() {
        return build(400, BYTES_400_PROVIDER);
    }

    public static @NonNull Mono<ServerResponse> resp415Provider() {
        return build(415, BYTES_415_PROVIDER);
    }

    public static @NonNull Mono<ServerResponse> resp429Burst() {
        return build(429, BYTES_429_BURST);
    }

    public static @NonNull Mono<ServerResponse> resp429Sustained() {
        return build(429, BYTES_429_SUSTAINED);
    }

    public static @NonNull Mono<ServerResponse> resp429Provider() {
        return build(429, BYTES_429_PROVIDER);
    }

    public static @NonNull Mono<ServerResponse> resp404() {
        return build(404, BYTES_404);
    }

    public static @NonNull Mono<ServerResponse> resp404Provider() {
        return build(404, BYTES_404_PROVIDER);
    }

    public static @NonNull Mono<ServerResponse> resp502Failed() {
        return build(502, BYTES_502_FAILED);
    }

    public static @NonNull Mono<ServerResponse> resp502TooLarge() {
        return build(502, BYTES_502_TOO_LARGE);
    }

    public static @NonNull Mono<ServerResponse> resp502InvalidJson() {
        return build(502, BYTES_502_INVALID_JSON);
    }

    /**
     * Serializes {@code message} into a JSON error body and returns the UTF-8 bytes.
     * Called only during static initialization.
     */
    private static byte @NonNull [] bytes(@NonNull String message) {
        return ("{\"error\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Builds a fresh {@link Mono}{@code <}{@link ServerResponse}{@code >} from
     * pre-existing bytes. Safe to call on any thread, including Netty event loop
     * threads — no blocking, no shared mutable state.
     */
    private static @NonNull Mono<ServerResponse> build(int status, byte @NonNull [] body) {
        return ServerResponse.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }
}
