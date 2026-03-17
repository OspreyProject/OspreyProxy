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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * Central store for all pre-serialized JSON error responses.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ErrorUtil {

    // Pre-computed response body strings
    private static final String BODY_200 = body("OK");
    public static final String BODY_400 = body("Bad Request");
    private static final String BODY_401 = body("Unauthorized");
    private static final String BODY_404 = body("Not Found");
    private static final String BODY_405 = body("Not Allowed");
    public static final String BODY_415 = body("Unsupported Media Type");
    private static final String BODY_429 = body("Too Many Requests");
    private static final String BODY_498 = body("Invalid Token");
    private static final String BODY_502 = body("Bad Gateway");
    private static final String BODY_503 = body("Service Unavailable");
    private static final String BODY_504 = body("Gateway Timeout");

    // Pre-built ResponseEntity instances for the most frequently returned errors
    public static final ResponseEntity<String> RESP_200 = build(HttpStatus.OK, BODY_200);
    public static final ResponseEntity<String> RESP_400 = build(HttpStatus.BAD_REQUEST, BODY_400);
    public static final ResponseEntity<String> RESP_401 = build(HttpStatus.BAD_REQUEST, BODY_401);
    public static final ResponseEntity<String> RESP_404 = build(HttpStatus.NOT_FOUND, BODY_404);
    public static final ResponseEntity<String> RESP_405 = build(HttpStatus.NOT_FOUND, BODY_405);
    public static final ResponseEntity<String> RESP_415 = build(HttpStatus.UNSUPPORTED_MEDIA_TYPE, BODY_415);
    public static final ResponseEntity<String> RESP_429 = build(HttpStatus.TOO_MANY_REQUESTS, BODY_429);
    public static final ResponseEntity<String> RESP_498 = build(HttpStatus.TOO_MANY_REQUESTS, BODY_498);
    public static final ResponseEntity<String> RESP_502 = build(HttpStatus.BAD_GATEWAY, BODY_502);
    public static final ResponseEntity<String> RESP_503 = build(HttpStatus.SERVICE_UNAVAILABLE, BODY_503);
    public static final ResponseEntity<String> RESP_504 = build(HttpStatus.GATEWAY_TIMEOUT, BODY_504);

    /**
     * Serializes {@code message} into a JSON error body string.
     * Called only during static initialization.
     *
     * @param message The error message to include in the JSON body.
     * @return A JSON string of the form {"error":"message"}.
     */
    private static @NonNull String body(@NonNull String message) {
        return "{\"error\":\"" + message + "\"}";
    }

    /**
     * Builds a {@link ResponseEntity} with the given {@code status} and pre-serialized {@code body}.
     * Content-Type is always {@code application/json; charset=UTF-8}.
     *
     * @param status The HTTP status code for the response.
     * @param body The pre-serialized JSON body string.
     * @return A {@link ResponseEntity} with the given status and body,
     *         ready to return from a controller method.
     */
    private static @NonNull ResponseEntity<String> build(@NonNull HttpStatus status,
                                                         @NonNull String body) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }
}
