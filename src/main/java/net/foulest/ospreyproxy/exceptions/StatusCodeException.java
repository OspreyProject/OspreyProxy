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

    private final transient ResponseEntity<String> status;

    /**
     * Constructs a new StatusCodeException with the specified HTTP status code and message.
     *
     * @param status The ResponseEntity containing the HTTP status code and message to be returned in the response.
     */
    @SuppressWarnings("NestedMethodCall")
    public StatusCodeException(@NonNull ResponseEntity<String> status) {
        super(String.valueOf(status.getStatusCode().value()));
        this.status = status;
    }
}
