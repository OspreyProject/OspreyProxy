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
package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Utility class for handling provider API keys read from environment variables at class-load
 * time. Centralizing the null/blank checks here keeps them independently unit-testable, since
 * each provider's own {@code API_KEY} is a static final field whose value (and therefore whose
 * branch outcome) is fixed for the lifetime of the JVM.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class APIKeyUtil {

    /**
     * Returns the given API key, or an empty string if it is {@code null}.
     *
     * @param apiKey The API key to check, typically read from an environment variable.
     * @return {@code apiKey} if non-null, or {@code ""} otherwise.
     */
    public static @NonNull String orEmpty(@Nullable String apiKey) {
        return apiKey != null ? apiKey : "";
    }

    /**
     * Validates that the given API key is present and non-blank.
     *
     * @param apiKey The API key to validate, typically read from an environment variable.
     * @param errorMessage The message to raise if the key is missing or blank.
     * @throws IllegalStateException if {@code apiKey} is {@code null} or blank.
     */
    public static void requireNonBlank(@Nullable String apiKey, @NonNull String errorMessage) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(errorMessage);
        }
    }
}
