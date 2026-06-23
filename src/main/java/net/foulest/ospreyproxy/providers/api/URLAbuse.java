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

import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Provider implementation for URLAbuse.
 */
@Slf4j
@Component
public class URLAbuse extends AbstractProvider {

    private static final String API_URL = "https://dbl.urlabuse.com/lookup?rd=";

    @Override
    public @NonNull String getDisplayName() {
        return "URLAbuse";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "urlabuse";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @SuppressWarnings("NestedMethodCall")
    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of("API-Key", getApiKey());
    }

    @Override
    public boolean isStripToHost() {
        // URLAbuse only accepts a bare domain; no scheme, path, query, or fragment.
        return true;
    }

    @Override
    public @NonNull String buildRequestUrl(@NonNull String url) {
        return API_URL + url;
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String url) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object result = data.get("attr");

            if ("BLACKLISTED".equals(result)) {
                return LookupResult.MALICIOUS;
            }

            if ("NOTBLACKLISTED".equals(result)) {
                return LookupResult.ALLOWED;
            }

            log.warn("[{}] Unexpected result value: {}", displayName, result);
            return LookupResult.FAILED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response: {} ({})",
                    displayName, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }
}
