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

    // AlphaMountain category IDs mapped to results
    private static final int CATEGORY_CSAM = 11;           // Child Sexual Abuse Material
    private static final int CATEGORY_PUA = 55;            // Potentially Unwanted Applications
    private static final int CATEGORY_MALICIOUS = 39;      // Malicious
    private static final int CATEGORY_PHISHING = 51;       // Phishing

    @PostConstruct
    public void validateConfig() {
        if (isEnabled() && (API_KEY == null || API_KEY.isBlank()
                || !UUID_PATTERN.matcher(API_KEY).matches())) {
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
    protected @NonNull Duration allowedCacheTtl() {
        return Duration.ofHours(24);
    }

    @Override
    protected @NonNull Duration blockedCacheTtl() {
        return Duration.ofHours(24);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object categoryBlock = data.get("category");

            if (!(categoryBlock instanceof Map<?, ?> categoryMap)) {
                log.warn("[{}] Response for '{}' missing 'category' block", displayName, normalizedUrl);
                return LookupResult.FAILED;
            }

            Object categoriesObj = categoryMap.get("categories");

            if (!(categoriesObj instanceof List<?> categories) || categories.isEmpty()) {
                log.info("[{}] No categories found for '{}'", displayName, normalizedUrl);
                return LookupResult.FAILED;
            }

            boolean isPhishing = categories.stream().anyMatch(c -> c instanceof Number n
                    && n.intValue() == CATEGORY_PHISHING);
            if (isPhishing) {
                return LookupResult.PHISHING;
            }

            boolean isMalicious = categories.stream().anyMatch(c -> c instanceof Number n
                    && n.intValue() == CATEGORY_MALICIOUS);
            if (isMalicious) {
                return LookupResult.MALICIOUS;
            }

            boolean hasUntrusted = categories.stream().anyMatch(c -> c instanceof Number n
                    && (n.intValue() == CATEGORY_CSAM || n.intValue() == CATEGORY_PUA));
            if (hasUntrusted) {
                return LookupResult.UNTRUSTED;
            }
            return LookupResult.ALLOWED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response for '{}': {} ({})",
                    displayName, normalizedUrl, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }
}
