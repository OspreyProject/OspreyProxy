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

class BforeAITest {

    private final BforeAI provider = new BforeAI();

    private static byte[] bytes(Map<String, Object> body) {
        return JacksonUtil.MAPPER.writeValueAsBytes(body);
    }

    @Test
    void getDisplayNameReturnsBforeAI() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("BforeAI");
    }

    @Test
    void getEndpointNameReturnsBforeai() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("bforeai");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl())
                .isEqualTo("https://api.bfore.ai/v2/feed/disruption?since=2000-01-01T00:00:00Z&url=");
    }

    @Test
    void isUsingOldHTTPReturnsTrue() {
        Assertions.assertThat(provider.isUsingOldHTTP()).isTrue();
    }

    @Test
    void isStripToBareHostReturnsTrue() {
        Assertions.assertThat(provider.isStripToBareHost()).isTrue();
    }

    @Test
    void isNotFoundValidResponseReturnsTrue() {
        Assertions.assertThat(provider.isNotFoundValidResponse()).isTrue();
    }

    @Test
    void buildRequestUrlAppendsUrlToApiUrl() {
        Assertions.assertThat(provider.buildRequestUrl("example.com"))
                .isEqualTo(provider.getApiUrl() + "example.com");
    }

    @Test
    void getHeadersReturnsExpectedHeaders() {
        Map<String, String> headers = provider.getHeaders();
        Assertions.assertThat(headers)
                .containsEntry("X-Authorization", provider.getApiKey())
                .containsEntry("Accept", "*/*");
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
        Assertions.assertThatThrownBy(() -> new BforeAI().validateConfig())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void acceptsApiProviderConfigurationWhenKeyIsPresent() {
        try (MockedStatic<APIKeyUtil> keys = Mockito.mockStatic(APIKeyUtil.class)) {
            Assertions.assertThatCode(() -> new BforeAI().validateConfig()).doesNotThrowAnyException();
            keys.verify(() -> APIKeyUtil.requireNonBlank(ArgumentMatchers.any(), ArgumentMatchers.anyString()));
        }
    }

    private static String readApiKey() throws ReflectiveOperationException {
        Field field = BforeAI.class.getDeclaredField("API_KEY");
        field.setAccessible(true);
        return (String) field.get(null);
    }

    @Test
    void interpretAllReturnsFailedOnInvalidJson() {
        LookupVerdict verdict = provider.interpretAll("not json".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllReturnsAllowedWhenItemsIsMissing() {
        Map<String, Object> data = new LinkedHashMap<>();
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsAllowedWhenItemsIsNotIterable() {
        Map<String, Object> data = Map.of("items", 42);
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsAllowedWhenItemsIsEmpty() {
        Map<String, Object> data = Map.of("items", List.of());
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsAllowedWhenItemIsNotAMap() {
        Map<String, Object> data = Map.of("items", List.of("not-a-map"));
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsAllowedWhenScoreIsMissing() {
        Map<String, Object> data = Map.of("items", List.of(Map.of()));
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsAllowedWhenScoreIsNotANumber() {
        Map<String, Object> data = Map.of("items", List.of(Map.of("score", "not-a-number")));
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void interpretAllReturnsMaliciousWhenScoreIsPresent() {
        Map<String, Object> data = Map.of("items", List.of(Map.of("score", 5)));
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.MALICIOUS);
    }

    @Test
    void interpretAllSkipsInvalidItemsBeforeFindingValidOne() {
        Map<String, Object> data = Map.of("items", List.of("bad", Map.of(), Map.of("score", 1)));
        LookupVerdict verdict = provider.interpretAll(bytes(data), "https://example.com");
        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.MALICIOUS);
    }
}
