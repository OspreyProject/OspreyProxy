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

import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.util.APIKeyUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.apache.hc.core5.http.Method;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class AlphaMountainTest {

    private final AlphaMountain provider = new AlphaMountain();

    private static byte[] bytes(Map<String, Object> body) {
        return JacksonUtil.MAPPER.writeValueAsBytes(body);
    }

    @Test
    void getDisplayNameReturnsAlphaMountain() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("AlphaMountain");
    }

    @Test
    void getEndpointNameReturnsAlphamountain() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("alphamountain");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://api.alphamountain.ai/category/uri");
    }

    @Test
    void getMethodReturnsPost() {
        Assertions.assertThat(provider.getMethod()).isEqualTo(Method.POST);
    }

    @Test
    void buildBodyReturnsExpectedFields() {
        Map<String, Object> body = provider.buildBody("https://example.com");
        Assertions.assertThat(body)
                .containsEntry("uri", "https://example.com")
                .containsEntry("license", provider.getApiKey())
                .containsEntry("version", 1)
                .containsEntry("type", "partner.info");
    }

    // The API key is read once into a static final field from the environment, so this only
    // exercises the branch matching whatever the environment actually provided. Both branches
    // of the underlying null check are covered directly in ApiKeyUtilTest.
    @Test
    void getApiKeyMatchesEnvironmentState() throws ReflectiveOperationException {
        String rawKey = readApiKey();
        Assertions.assertThat(provider.getApiKey()).isEqualTo(APIKeyUtil.orEmpty(rawKey));
    }

    @Test
    void validateConfigMatchesEnvironmentState() throws ReflectiveOperationException {
        String rawKey = readApiKey();

        if (rawKey == null || rawKey.isBlank()) {
            Assertions.assertThatThrownBy(provider::validateConfig)
                    .isInstanceOf(IllegalStateException.class);
        } else {
            Assertions.assertThatCode(provider::validateConfig).doesNotThrowAnyException();
        }
    }

    @Test
    void rejectsMissingApiProviderConfiguration() {
        Assertions.assertThatThrownBy(() -> new AlphaMountain().validateConfig())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void acceptsApiProviderConfigurationWhenKeyIsPresent() {
        try (MockedStatic<APIKeyUtil> keys = Mockito.mockStatic(APIKeyUtil.class)) {
            Assertions.assertThatCode(() -> new AlphaMountain().validateConfig()).doesNotThrowAnyException();
            keys.verify(() -> APIKeyUtil.requireNonBlank(ArgumentMatchers.any(), ArgumentMatchers.anyString()));
        }
    }

    private static String readApiKey() throws ReflectiveOperationException {
        Field field = AlphaMountain.class.getDeclaredField("API_KEY");
        field.setAccessible(true);
        return (String) field.get(null);
    }

    @Test
    void interpretAllReturnsFailedOnInvalidJson() {
        LookupVerdict verdict = provider.interpretAll("not json".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsFailedWhenCategoryIsMissing() {
        Map<String, Object> data = new LinkedHashMap<>();
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsFailedWhenCategoryIsNotAMap() {
        Map<String, Object> data = Map.of("category", "not-a-map");
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsFailedWhenCategoriesIsMissing() {
        Map<String, Object> category = Map.of("confidence", 0.99);
        Map<String, Object> data = Map.of("category", category);
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsFailedWhenCategoriesIsNotAList() {
        Map<String, Object> category = Map.of("categories", "not-a-list");
        Map<String, Object> data = Map.of("category", category);
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsFailedWhenCategoriesIsEmpty() {
        Map<String, Object> category = Map.of("categories", List.of());
        Map<String, Object> data = Map.of("category", category);
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsPhishingWhenConfidenceMeetsThreshold() {
        Map<String, Object> category = new LinkedHashMap<>();
        category.put("categories", List.of(51));
        category.put("confidence", 0.98);
        category.put("source", "rt-high");
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.PHISHING);
    }

    @Test
    void interpretAllReturnsAllowedWhenPhishingConfidenceBelowThresholdAndMetadataMissing() {
        Map<String, Object> category = Map.of("categories", List.of(51));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsMaliciousWhenSourceIsRtMediumRegardlessOfConfidence() {
        Map<String, Object> category = new LinkedHashMap<>();
        category.put("categories", List.of(39));
        category.put("confidence", 0.1);
        category.put("source", "rt-medium");
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.MALICIOUS);
    }

    @Test
    void interpretAllReturnsMaliciousWhenConfidenceMeetsThresholdForNonRtMediumSource() {
        Map<String, Object> category = new LinkedHashMap<>();
        category.put("categories", List.of(39));
        category.put("confidence", 0.96);
        category.put("source", "other");
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.MALICIOUS);
    }

    @Test
    void interpretAllReturnsAllowedWhenMaliciousConfidenceBelowThreshold() {
        Map<String, Object> category = Map.of("categories", List.of(39));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsSuspiciousForSpamCategory() {
        Map<String, Object> category = Map.of("categories", List.of(70));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.SUSPICIOUS);
    }

    @Test
    void interpretAllReturnsSuspiciousForSuspiciousCategory() {
        Map<String, Object> category = Map.of("categories", List.of(72));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.SUSPICIOUS);
    }

    @Test
    void interpretAllReturnsNewlyRegisteredCategory() {
        Map<String, Object> category = Map.of("categories", List.of(87));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.NEWLY_REGISTERED);
    }

    @Test
    void interpretAllReturnsDynamicDnsCategory() {
        Map<String, Object> category = Map.of("categories", List.of(85));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.DYNAMIC_DNS);
    }

    @Test
    void interpretAllReturnsMaliciousForCsamCategory() {
        Map<String, Object> category = Map.of("categories", List.of(11));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.MALICIOUS);
    }

    @Test
    void interpretAllReturnsSuspiciousForPupCategory() {
        Map<String, Object> category = Map.of("categories", List.of(55));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.SUSPICIOUS);
    }

    @Test
    void interpretAllReturnsContentPolicyCategory() {
        Map<String, Object> category = Map.of("categories", List.of(48));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.PARKED);
    }

    @Test
    void interpretAllReturnsAllowedWhenNoCategoriesMatch() {
        // Includes a non-Number element to cover the "obj instanceof Number" false branch
        // of hasCategory's anyMatch, alongside the Number-but-unequal branch from 9999.
        Map<String, Object> category = Map.of("categories", List.of("not-a-number", 9999));
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsMultipleResultsInSeverityOrder() {
        Map<String, Object> category = new LinkedHashMap<>();
        category.put("categories", List.of(51, 39));
        category.put("confidence", 0.99);
        category.put("source", "rt-medium");
        Map<String, Object> data = Map.of("category", category);

        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.PHISHING, LookupResult.MALICIOUS);
    }
}
