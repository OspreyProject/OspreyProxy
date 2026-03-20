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
package net.foulest.ospreyproxy.config;

import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.ErrorUtil;
import org.apache.catalina.connector.ClientAbortException;
import org.jspecify.annotations.NonNull;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Global exception handler for Spring MVC.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles requests whose body exceeds the configured size limit.
     * Tomcat rejects these before any controller code runs.
     *
     * @param ex The exception to handle.
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<String> handleMaxUploadSize(@NonNull MaxUploadSizeExceededException ex) {
        log.warn("Request body exceeded size limit: {}", ex.getMessage());
        return ErrorUtil.RESP_400;
    }

    /**
     * Handles requests for unmapped paths (the MVC equivalent of 404).
     *
     * @param ignored The exception to handle (ignored).
     */
    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public ResponseEntity<String> handleNoResource(Exception ignored) {
        return ErrorUtil.RESP_404;
    }

    /**
     * Handles I/O errors while reading the request body.
     *
     * @param ex The exception to handle.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleNotReadable(@NonNull HttpMessageNotReadableException ex) {
        Throwable cause = ex.getCause();

        if (!(cause instanceof ClientAbortException)) {
            log.warn("Could not read request body: {}", ex.getMessage());
        }
        return ErrorUtil.RESP_400;
    }

    /**
     * Handles requests that use an unsupported HTTP method (e.g. GET on a POST-only endpoint).
     *
     * @param ignored The exception to handle (ignored).
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<String> handleMethodNotAllowed(Exception ignored) {
        return ErrorUtil.RESP_405;
    }

    /**
     * Catch-all for unexpected exceptions not handled elsewhere.
     *
     * @param ex The exception to handle.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleUnexpected(Exception ex) {
        log.error("Unexpected exception: {} | {}", ex.getMessage(), ex.getClass().getName(), ex);
        return ErrorUtil.RESP_502;
    }
}
