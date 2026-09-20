/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
package net.foulest.ospreyproxy.exceptions;

import net.foulest.ospreyproxy.util.ErrorUtil;
import org.apache.catalina.connector.ClientAbortException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.io.EOFException;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleStatusCodeReturnsExceptionStatus() {
        StatusCodeException ex = new StatusCodeException(ErrorUtil.RESP_429);
        ResponseEntity<String> response = handler.handleStatusCode(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_429);
    }

    @Test
    void handleMaxUploadSizeReturns400() {
        MaxUploadSizeExceededException ex = new MaxUploadSizeExceededException(1024L);
        ResponseEntity<String> response = handler.handleMaxUploadSize(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_400);
    }

    @Test
    void handleNoResourceReturns404ForNoResourceFoundException() {
        NoResourceFoundException ex = new NoResourceFoundException(HttpMethod.GET, "/missing", "/missing");
        ResponseEntity<String> response = handler.handleNoResource(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_404);
    }

    @Test
    void handleNoResourceReturns404ForNoHandlerFoundException() {
        NoHandlerFoundException ex = new NoHandlerFoundException("GET", "/missing", null);
        ResponseEntity<String> response = handler.handleNoResource(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_404);
    }

    @Test
    void handleNotReadableReturns400WhenCauseIsClientAbortException() {
        Exception ex = new Exception("body not readable", new ClientAbortException());
        ResponseEntity<String> response = handler.handleNotReadable(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_400);
    }

    @Test
    void handleNotReadableReturns400WhenCauseIsEOFException() {
        Exception ex = new Exception("body not readable", new EOFException());
        ResponseEntity<String> response = handler.handleNotReadable(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_400);
    }

    @Test
    void handleNotReadableReturns400WhenCauseIsOtherThrowable() {
        Exception ex = new Exception("body not readable", new RuntimeException("boom"));
        ResponseEntity<String> response = handler.handleNotReadable(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_400);
    }

    @Test
    void handleNotReadableReturns400WhenCauseIsNull() {
        Exception ex = new Exception("body not readable");
        ResponseEntity<String> response = handler.handleNotReadable(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_400);
    }

    @Test
    void handleMethodNotAllowedReturns405() {
        HttpRequestMethodNotSupportedException ex = new HttpRequestMethodNotSupportedException("PUT");
        ResponseEntity<String> response = handler.handleMethodNotAllowed(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_405);
    }

    @Test
    void handleUnexpectedReturns500() {
        Exception ex = new RuntimeException("unexpected failure");
        ResponseEntity<String> response = handler.handleUnexpected(ex);
        Assertions.assertThat(response).isSameAs(ErrorUtil.RESP_500);
    }
}
