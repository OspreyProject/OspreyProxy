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
package net.foulest.ospreyproxy.providers;

import jakarta.annotation.PostConstruct;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Provider implementation for PrecisionSec.
 */
@Component
public class PrecisionSecProvider implements Provider {

    private static final String API_KEY = System.getenv("PRECISIONSEC_API_KEY");
    private static final String API_URL = "https://api.precisionsec.com/check_url/";
    private static final String UUID_PATTERN = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    @PostConstruct
    public void validateConfig() {
        // Check if the key is blank or doesn't match UUID spec
        if (API_KEY == null || API_KEY.isBlank() || !API_KEY.matches(UUID_PATTERN)) {
            throw new IllegalStateException("PRECISIONSEC_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NonNull String getMethod() {
        return "GET";
    }

    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of("API-Key", API_KEY);
    }

    @Override
    public @NonNull String buildRequestUrl(@NonNull String url) {
        String encoded = URLEncoder.encode(url, StandardCharsets.UTF_8);
        return API_URL + encoded;
    }
}
