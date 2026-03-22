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
package net.foulest.ospreyproxy.providers.api;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Provider implementation for PrecisionSec.
 */
@Slf4j
@Component
public class PrecisionSec extends AbstractProvider {

    private static final String API_KEY = System.getenv("PRECISIONSEC_API_KEY");
    private static final String API_URL = "https://api.precisionsec.com/check_domain/";

    @PostConstruct
    public void validateConfig() {
        if (isEnabled() && (API_KEY == null || API_KEY.isBlank()
                || !UUID_PATTERN.matcher(API_KEY).matches())) {
            throw new IllegalStateException("PRECISIONSEC_API_KEY environment variable is not set");
        }
    }

    @Override
    public @NonNull String getDisplayName() {
        return "PrecisionSec";
    }

    @Override
    public @NonNull String getShortName() {
        return "precisionSec";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "precisionsec";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NonNull String getApiKey() {
        return API_KEY != null ? API_KEY : "";
    }

    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of("API-Key", getApiKey());
    }

    @Override
    public boolean stripToHost() {
        // PrecisionSec only accepts a bare domain; no scheme, path, query, or fragment.
        return true;
    }

    @Override
    public @NonNull String buildRequestUrl(@NonNull String url) {
        return API_URL + url;
    }

    /**
     * Parses the PrecisionSec response and maps the result string to a {@link LookupResult}.
     * <p>
     * Response shape: {@code {"result": "<string>"}}
     * <p>
     * Known result values: {@code "Malicious"} → MALICIOUS, {@code "No result"} → ALLOWED.
     * Any other value is treated as FAILED and logged for investigation.
     */
    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object result = data.get("result");

            if ("Malicious".equals(result)) {
                return LookupResult.MALICIOUS;
            }

            if ("No result".equals(result)) {
                return LookupResult.ALLOWED;
            }

            log.warn("[{}] Unexpected result value for '{}': {}", displayName, normalizedUrl, result);
            return LookupResult.FAILED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response for '{}': {} ({})",
                    displayName, normalizedUrl, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }
}
