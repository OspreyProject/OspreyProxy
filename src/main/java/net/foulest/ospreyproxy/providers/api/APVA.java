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

import java.util.List;
import java.util.Map;

/**
 * Provider implementation for APVA.
 */
@Slf4j
@Component
public class APVA extends AbstractProvider {

    private static final String API_URL = "https://api.antiphish.org/v1/lookup?host=";

    @Override
    public @NonNull String getDisplayName() {
        return "APVA";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "apva";
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
    public boolean isStripToHost() {
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
            List<Map<String, Object>> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.LIST_OF_MAP_TYPE);

            if (data.isEmpty()) {
                return LookupResult.ALLOWED;
            }

            for (Map<String, Object> entry : data) {
                if ("phishing".equals(entry.get("threat_type"))) {
                    return LookupResult.PHISHING;
                }

                if ("malicious".equals(entry.get("threat_type"))) {
                    return LookupResult.MALICIOUS;
                }

                if ("malware".equals(entry.get("threat_type"))) {
                    return LookupResult.MALICIOUS;
                }
            }

            log.warn("[{}] Unexpected result value: {}", displayName, data);
            return LookupResult.FAILED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response: {} ({})",
                    displayName, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }
}
