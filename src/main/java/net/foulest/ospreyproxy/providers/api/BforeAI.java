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
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Provider implementation for BforeAI.
 */
@Slf4j
@Component
public class BforeAI extends AbstractProvider {

    private static final String API_KEY = System.getenv("BFORE_AI_API_KEY");
    private static final String API_URL = "https://api.bfore.ai/v2/feed/intel?since=2000-01-01T00:00:00Z&url=";

    /**
     * Validates the provider configuration after construction.
     * Ensures that if the provider is enabled, the API key is set and not blank.
     */
    @PostConstruct
    public void validateConfig() {
        if (API_KEY == null || API_KEY.isBlank()) {
            throw new IllegalStateException("BFORE_AI_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getDisplayName() {
        return "BforeAI";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "bforeai";
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
    public boolean isUsingOldHTTP() {
        return true;
    }

    @Override
    public boolean isStripToBareHost() {
        return true;
    }

    @Override
    public boolean isNotFoundValidResponse() {
        return true;
    }

    @Override
    public @NonNull String buildRequestUrl(@NonNull String url) {
        return API_URL + url;
    }

    @SuppressWarnings("NestedMethodCall")
    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of(
                "X-Authorization", getApiKey(),
                "Accept", "*/*"
        );
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupVerdict interpretAll(byte @NonNull [] responseBytes, @NonNull String url) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object itemsObj = data.get("items");

            // Returns if the 'items' field is missing or not an array
            if (!(itemsObj instanceof Iterable<?> items)) {
                return LookupVerdict.FAILED;
            }

            for (Object itemObj : items) {
                // Returns if the item is not a map
                if (!(itemObj instanceof Map<?, ?> itemMap)) {
                    continue;
                }

                Object scoreObj = itemMap.get("score");

                // Returns if the 'score' field is missing or not a number
                if (!(scoreObj instanceof Number score)) {
                    continue;
                }

                // If the score is 0.8 or higher, classify the URL as malicious
                if (score.doubleValue() >= 0.8) {
                    return LookupVerdict.of(LookupResult.MALICIOUS);
                }
            }
            return LookupVerdict.ALLOWED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response: {} ({})", displayName, e.getMessage(), e.getClass().getName());
            return LookupVerdict.FAILED;
        }
    }
}
