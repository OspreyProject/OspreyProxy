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
import org.apache.hc.core5.http.Method;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Provider implementation for AlphaMountain.
 */
@Slf4j
@Component
public class AlphaMountain extends AbstractProvider {

    private static final String API_KEY = System.getenv("ALPHAMOUNTAIN_API_KEY");
    private static final String API_URL = "https://api.alphamountain.ai/category/uri";

    /**
     * Constructor for the provider, setting the cache durations for allowed and blocked results.
     */
    public AlphaMountain() {
        super(Duration.ofHours(24), Duration.ofHours(24));
    }

    /**
     * Validates the provider configuration after construction.
     * Ensures that if the provider is enabled, the API key is set and not blank.
     */
    @PostConstruct
    public void validateConfig() {
        if (API_KEY == null || API_KEY.isBlank()) {
            throw new IllegalStateException("ALPHAMOUNTAIN_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getDisplayName() {
        return "AlphaMountain";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "alphamountain";
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

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Map<String, Object> buildBody(@NonNull String url) {
        return Map.of(
                "uri", url,
                "license", getApiKey(),
                "version", 1,
                "type", "partner.info"
        );
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupVerdict interpretAll(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object categoryBlock = data.get("category");

            if (!(categoryBlock instanceof Map<?, ?> categoryMap)) {
                log.warn("[{}] Response missing 'category' block", displayName);
                return LookupVerdict.FAILED;
            }

            Object categoriesObj = categoryMap.get("categories");

            if (!(categoriesObj instanceof List<?> categories) || categories.isEmpty()) {
                log.warn("[{}] No categories found", displayName);
                return LookupVerdict.FAILED;
            }

            double confidence = categoryMap.get("confidence") instanceof Number num ? num.doubleValue() : Double.NaN;
            String source = categoryMap.get("source") instanceof String sourceValue ? sourceValue : "";
            List<LookupResult> results = new ArrayList<>();

            // Phishing
            if (hasCategory(categories, 51) && confidence >= 0.970767) {
                results.add(LookupResult.PHISHING);
            }

            // Malicious
            if (hasCategory(categories, 39)
                    && ("rt-medium".equals(source) || confidence >= 0.95307525)) {
                results.add(LookupResult.MALICIOUS);
            }

            // Spam
            if (hasCategory(categories, 70) && confidence >= 0.970767) {
                results.add(LookupResult.MALICIOUS);
            }

            // Suspicious
            if (hasCategory(categories, 72)) {
                results.add(LookupResult.SUSPICIOUS);
            }

            // Newly Registered
            if (hasCategory(categories, 87)) {
                results.add(LookupResult.NEWLY_REGISTERED);
            }

            // Dynamic DNS
            if (hasCategory(categories, 85)) {
                results.add(LookupResult.DYNAMIC_DNS);
            }
            return results.isEmpty() ? LookupVerdict.ALLOWED : LookupVerdict.of(results);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response: {} ({})",
                    displayName, e.getMessage(), e.getClass().getName());
            return LookupVerdict.FAILED;
        }
    }

    /**
     * Returns whether the AlphaMountain {@code categories} array contains the given numeric category ID.
     *
     * @param categories The raw {@code categories} list from the response.
     * @param categoryId The AlphaMountain category ID to look for.
     * @return {@code true} if the ID is present.
     */
    private static boolean hasCategory(@NonNull List<?> categories, int categoryId) {
        return categories.stream().anyMatch(obj -> obj instanceof Number num && num.intValue() == categoryId);
    }
}
