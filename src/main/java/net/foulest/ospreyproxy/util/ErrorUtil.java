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
    public static final byte[] BYTES_400 = bytes("Bad Request");

    // 404 Not Found
    private static final byte[] BYTES_404 = bytes("Not found");

    // 415 Unsupported Media Type
    public static final byte[] BYTES_415 = bytes("Unsupported Media Type");

    // 429 Too Many Requests
    private static final byte[] BYTES_429 = bytes("Too Many Requests");

    // 502 Bad Gateway
    private static final byte[] BYTES_502 = bytes("Bad Gateway");

    // 504 Gateway Timeout
    private static final byte[] BYTES_504 = bytes("Gateway Timeout");

    public static @NonNull Mono<ServerResponse> resp200() {
        return build(200, BYTES_200_OK);
    }

    public static @NonNull Mono<ServerResponse> resp400() {
        return build(400, BYTES_400);
    }

    public static @NonNull Mono<ServerResponse> resp404() {
        return build(404, BYTES_404);
    }

    public static @NonNull Mono<ServerResponse> resp415() {
        return build(415, BYTES_415);
    }

    public static @NonNull Mono<ServerResponse> resp429() {
        return build(429, BYTES_429);
    }

    public static @NonNull Mono<ServerResponse> resp502() {
        return build(502, BYTES_502);
    }

    public static @NonNull Mono<ServerResponse> resp504() {
        return build(504, BYTES_504);
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
     * threads: no blocking, no shared mutable state.
     * <p>
     * Uses {@code bodyValue(String)} rather than {@code bodyValue(byte[])} because
     * Spring WebFlux's functional {@link ServerResponse} routes {@code byte[]} through
     * {@code Jackson2JsonEncoder}, which base64-encodes it. A {@code String} value is
     * handled by {@code CharSequenceEncoder} and written verbatim.
     */
    private static @NonNull Mono<ServerResponse> build(int status, byte @NonNull [] body) {
        return ServerResponse.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new String(body, StandardCharsets.UTF_8));
    }
}
