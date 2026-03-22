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
package net.foulest.ospreyproxy.exceptions;

import lombok.Getter;
import org.jspecify.annotations.NonNull;
import org.springframework.http.ResponseEntity;

/**
 * Custom exception class that encapsulates an HTTP status code and message to be returned in the response.
 * This allows us to throw this exception from anywhere in the code and have it automatically translated into
 * the appropriate HTTP response.
 */
@Getter
public class StatusCodeException extends RuntimeException {

    // The HTTP status to return
    private final ResponseEntity<String> status;

    @SuppressWarnings("NestedMethodCall")
    public StatusCodeException(@NonNull ResponseEntity<String> status) {
        super(String.valueOf(status.getStatusCode().value()));
        this.status = status;
    }
}
