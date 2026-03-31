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
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.apache.hc.core5.http.Method;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Provider implementation for ChainPatrol.
 */
@Slf4j
@Component
public class ChainPatrol extends AbstractProvider {

    private static final String API_KEY = System.getenv("CHAINPATROL_API_KEY");
    private static final String API_URL = "https://app.chainpatrol.io/api/v2/asset/check";

    @PostConstruct
    public void validateConfig() {
        if (isEnabled() && (API_KEY == null || API_KEY.isBlank()
                || !UUID_PATTERN.matcher(API_KEY).matches())) {
            throw new IllegalStateException("CHAINPATROL_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getDisplayName() {
        return "ChainPatrol";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "chainpatrol";
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
    public @NonNull Method getMethod() {
        return Method.POST;
    }

    @SuppressWarnings("NestedMethodCall")
    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of(
                "X-API-KEY", getApiKey()
        );
    }

    @Override
    public @NonNull Map<String, Object> buildBody(@NonNull String url) {
        return Map.of(
                "content", url
        );
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object status = data.get("status");

            if (!(status instanceof String statusStr)) {
                log.warn("[{}] Response for '{}' missing or invalid 'status' field", displayName, normalizedUrl);
                return LookupResult.FAILED;
            }

            switch (statusStr) {
                case "BLOCKED" -> {
                    return LookupResult.PHISHING;
                }
                case "UNKNOWN", "ALLOWED" -> {
                    return LookupResult.ALLOWED;
                }
                default -> {
                    log.warn("[{}] Unexpected 'status' value for '{}': {}", displayName, normalizedUrl, statusStr);
                    return LookupResult.FAILED;
                }
            }
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response for '{}': {} ({})",
                    displayName, normalizedUrl, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }
}
