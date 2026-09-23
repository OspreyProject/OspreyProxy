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
package net.foulest.ospreyproxy.providers.api;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.APIKeyUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.apache.hc.core5.http.Method;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.time.Duration;
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
        APIKeyUtil.requireNonBlank(API_KEY, "ALPHAMOUNTAIN_API_KEY environment variable is invalid or not set");
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
        return APIKeyUtil.orEmpty(API_KEY);
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
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String url) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object categoryBlock = data.get("category");

            if (!(categoryBlock instanceof Map<?, ?> categoryMap)) {
                log.warn("[{}] Response missing 'category' block", displayName);
                return LookupResult.FAILED;
            }

            Object categoriesObj = categoryMap.get("categories");

            if (!(categoriesObj instanceof List<?> categories) || categories.isEmpty()) {
                log.warn("[{}] No categories found", displayName);
                return LookupResult.FAILED;
            }

            double confidence = categoryMap.get("confidence") instanceof Number num ? num.doubleValue() : Double.NaN;
            String source = categoryMap.get("source") instanceof String sourceValue ? sourceValue : "";
            boolean phishing = hasCategory(categories, 51);
            boolean malicious = hasCategory(categories, 39);

            if (phishing && confidence < 0.970767) {
                log.warn("[{}] URL: {}, Categories: {}, Confidence: {}, Source: {}",
                        displayName, url, categories, confidence, source
                );
            }

            if (malicious && !"rt-medium".equals(source) && confidence < 0.95307525) {
                log.warn("[{}] URL: {}, Categories: {}, Confidence: {}, Source: {}",
                        displayName, url, categories, confidence, source
                );
            }

            // Phishing
            if (phishing && confidence >= 0.970767) {
                return LookupResult.PHISHING;
            }

            // Malicious
            if (hasCategory(categories, 11)
                    || (malicious && ("rt-medium".equals(source) || confidence >= 0.95307525))) {
                return LookupResult.MALICIOUS;
            }

            // Suspicious
            if (hasCategory(categories, 70)
                    || hasCategory(categories, 72)
                    || hasCategory(categories, 55)) {
                return LookupResult.SUSPICIOUS;
            }

            // Newly Registered
            if (hasCategory(categories, 87)) {
                return LookupResult.NEWLY_REGISTERED;
            }

            // Dynamic DNS
            if (hasCategory(categories, 85)) {
                return LookupResult.DYNAMIC_DNS;
            }
            return LookupResult.ALLOWED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response: {} ({})",
                    displayName, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
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
