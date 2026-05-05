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
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;
import org.springframework.http.ResponseEntity;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;

/**
 * Custom exception class that encapsulates an HTTP status code and message to be returned in the response.
 * This allows us to throw this exception from anywhere in the code and have it automatically translated into
 * the appropriate HTTP response.
 */
@Getter
public class StatusCodeException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;
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

    @Serial
    @Contract(value = "_ -> fail", pure = true)
    private void readObject(@NonNull ObjectInputStream in) throws NotSerializableException {
        throw new NotSerializableException("StatusCodeException is not serializable");
    }

    @Serial
    @Contract(value = "_ -> fail", pure = true)
    private void writeObject(@NonNull ObjectOutputStream out) throws NotSerializableException {
        throw new NotSerializableException("StatusCodeException is not serializable");
    }
}
