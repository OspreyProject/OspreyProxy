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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Provider implementation for Google Safe Browsing (Lookup API v4, {@code threatMatches:find}).
 * <p>
 * Unlike the GET-style API providers, Google Safe Browsing is a POST endpoint that takes the
 * API key as a query parameter and the target URL inside a JSON body. A single URL is sent per
 * request (the proxy fans out per-URL), so any non-empty {@code matches} array applies to that URL.
 */
@Slf4j
@Component
public class SafeBrowsing extends AbstractProvider {

    private static final String API_KEY = System.getenv("SAFEBROWSING_API_KEY");
    private static final String API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

    private static final String CLIENT_ID = "osprey";
    private static final String CLIENT_VERSION = "1.0.0";

    private static final List<String> THREAT_TYPES = List.of(
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
    );

    /**
     * Constructor for the provider, setting the cache durations for allowed and blocked results.
     */
    public SafeBrowsing() {
        super(Duration.ofHours(24), Duration.ofHours(48));
    }

    /**
     * Validates the provider configuration after construction.
     * Ensures that if the provider is enabled, the API key is set and not blank.
     */
    @PostConstruct
    public void validateConfig() {
        if (API_KEY == null || API_KEY.isBlank()) {
            throw new IllegalStateException("SAFEBROWSING_API_KEY environment variable is not set");
        }
    }

    @Override
    public @NonNull String getDisplayName() {
        return "Google Safe Browsing";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "safebrowsing";
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
    public boolean isUsingOldHTTP() {
        return true;
    }

    @SuppressWarnings("NestedMethodCall")
    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of("Content-Type", "application/json");
    }

    @Override
    public @NonNull String buildRequestUrl(@NonNull String url) {
        return API_URL + "?key=" + URLEncoder.encode(getApiKey(), StandardCharsets.UTF_8);
    }

    @SuppressWarnings("NestedMethodCall")
    @Override
    public @NonNull Map<String, Object> buildBody(@NonNull String url) {
        return Map.of(
                "client", Map.of(
                        "clientId", CLIENT_ID,
                        "clientVersion", CLIENT_VERSION
                ),
                "threatInfo", Map.of(
                        "threatTypes", THREAT_TYPES,
                        "platformTypes", List.of("ANY_PLATFORM"),
                        "threatEntryTypes", List.of("URL"),
                        "threatEntries", List.of(Map.of("url", url))
                )
        );
    }

    @Override
    @SuppressWarnings("OverlyComplexMethod")
    public @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        String displayName = getDisplayName();

        try {
            Map<String, Object> data = JacksonUtil.MAPPER.readValue(responseBytes, JacksonUtil.MAP_TYPE_OBJECT);
            Object matchesObj = data.get("matches");

            if (!(matchesObj instanceof List<?> matches) || matches.isEmpty()) {
                return LookupResult.ALLOWED;
            }

            boolean phishing = false;
            boolean malicious = false;

            for (Object matchObj : matches) {
                if (!(matchObj instanceof Map<?, ?> match)) {
                    continue;
                }

                Object threatType = match.get("threatType");

                if ("SOCIAL_ENGINEERING".equals(threatType)) {
                    phishing = true;
                } else if ("MALWARE".equals(threatType)
                        || "UNWANTED_SOFTWARE".equals(threatType)
                        || "POTENTIALLY_HARMFUL_APPLICATION".equals(threatType)) {
                    malicious = true;
                } else {
                    log.warn("[{}] Match with unexpected threatType: {}", displayName, threatType);
                    malicious = true;
                }
            }

            if (phishing) {
                return LookupResult.PHISHING;
            }

            if (malicious) {
                return LookupResult.MALICIOUS;
            }

            log.warn("[{}] Non-empty matches produced no verdict", displayName);
            return LookupResult.FAILED;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to interpret response: {} ({})",
                    displayName, e.getMessage(), e.getClass().getName());
            return LookupResult.FAILED;
        }
    }
}
