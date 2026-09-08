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
     * AlphaMountain category IDs mapped to Osprey content policy results. Content
     * categories are informational to the extension: they block only when the client's
     * block-category toggle for the result is enabled, so no confidence gate applies here.
     * Security categories are handled separately in {@link #interpretAll} with their gates.
     */
    private static final Map<Integer, LookupResult> CONTENT_CATEGORY_MAP = Map.ofEntries(
            Map.entry(48, LookupResult.PARKED),
            Map.entry(3, LookupResult.ADULT_CONTENT),
            Map.entry(38, LookupResult.ADULT_CONTENT),
            Map.entry(44, LookupResult.ADULT_CONTENT),
            Map.entry(47, LookupResult.ADULT_CONTENT),
            Map.entry(54, LookupResult.ADULT_CONTENT),
            Map.entry(65, LookupResult.SEX_EDUCATION),
            Map.entry(13, LookupResult.DATING),
            Map.entry(24, LookupResult.GAMBLING),
            Map.entry(15, LookupResult.DRUGS),
            Map.entry(40, LookupResult.DRUGS),
            Map.entry(4, LookupResult.ALCOHOL_TOBACCO),
            Map.entry(74, LookupResult.ALCOHOL_TOBACCO),
            Map.entry(82, LookupResult.WEAPONS),
            Map.entry(28, LookupResult.HATE_DISCRIMINATION),
            Map.entry(19, LookupResult.VIOLENCE_GORE),
            Map.entry(80, LookupResult.VIOLENCE_GORE),
            Map.entry(52, LookupResult.PIRACY),
            Map.entry(27, LookupResult.HACKING),
            Map.entry(67, LookupResult.SOCIAL_MEDIA),
            Map.entry(7, LookupResult.STREAMING_MEDIA),
            Map.entry(42, LookupResult.STREAMING_MEDIA),
            Map.entry(79, LookupResult.STREAMING_MEDIA),
            Map.entry(25, LookupResult.GAMES),
            Map.entry(10, LookupResult.CHAT_MESSAGING),
            Map.entry(20, LookupResult.FILE_SHARING),
            Map.entry(49, LookupResult.FILE_SHARING),
            Map.entry(6, LookupResult.SHOPPING_AUCTIONS),
            Map.entry(66, LookupResult.SHOPPING_AUCTIONS),
            Map.entry(37, LookupResult.JOB_SEARCH),
            Map.entry(17, LookupResult.WEBMAIL),
            Map.entry(61, LookupResult.REMOTE_ACCESS),
            Map.entry(83, LookupResult.AI_APPLICATIONS),
            Map.entry(84, LookupResult.CRYPTOCURRENCY)
    );

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
    public @NonNull LookupVerdict interpretAll(byte @NonNull [] responseBytes, @NonNull String url) {
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
            if (hasCategory(categories, 51)) {
                if (confidence >= 0.970767) {
                    results.add(LookupResult.PHISHING);
                } else {
                    log.warn("[{}] URL: {}, Categories: {}, Confidence: {}, Source: {}", url, displayName, categories, confidence, source);
                }
            }

            // Malicious
            if (hasCategory(categories, 39)) {
                if ("rt-medium".equals(source)) {
                    results.add(LookupResult.MALICIOUS);
                } else if (confidence >= 0.95307525) {
                    results.add(LookupResult.MALICIOUS);
                } else {
                    log.warn("[{}] URL: {}, Categories: {}, Confidence: {}, Source: {}", url, displayName, categories, confidence, source);
                }
            }

            // Spam
            if (hasCategory(categories, 70)) {
                results.add(LookupResult.SUSPICIOUS);
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

            // Child sexual abuse material blocks unconditionally as malicious
            if (hasCategory(categories, 11)) {
                results.add(LookupResult.MALICIOUS);
            }

            // Potentially Unwanted Programs corroborate as suspicious
            if (hasCategory(categories, 55)) {
                results.add(LookupResult.SUSPICIOUS);
            }

            // Content policy categories: emitted for the extension's block-category
            // toggles; harmless to clients without the toggle enabled
            for (Map.Entry<Integer, LookupResult> entry : CONTENT_CATEGORY_MAP.entrySet()) {
                if (hasCategory(categories, entry.getKey())) {
                    results.add(entry.getValue());
                }
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
