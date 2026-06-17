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
import org.apache.hc.core5.http.Method;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;

/**
 * Provider implementation for iZOOlogic.
 */
@Slf4j
@Component
public class IZOOlogic extends AbstractProvider {

    private static final String API_URL = "https://opencti.izoolabs.com/api/CTI/GetUrlVerdict";

    /**
     * Constructor for the provider, setting the cache durations for allowed and blocked results.
     */
    public IZOOlogic() {
        super(Duration.ofHours(24), Duration.ofHours(24));
    }

    @Override
    public @NonNull String getDisplayName() {
        return "iZOOlogic";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "izoologic";
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
    public @NonNull Method getMethod() {
        return Method.POST;
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Map<String, Object> buildBody(@NonNull String url) {
        return Map.of(
                "url", url
        );
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object result = data.get("result");

            if ("Malicious or Phishing Url".equals(result)) {
                return LookupResult.MALICIOUS;
            }

            if ("Clean".equals(result) || "Suspicious-Activity".equals(result)) {
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
