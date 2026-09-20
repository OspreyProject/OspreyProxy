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
import java.util.Map;

class ChainPatrolTest {

    private final ChainPatrol provider = new ChainPatrol();

    private static byte[] bytes(Map<String, Object> body) {
        return JacksonUtil.MAPPER.writeValueAsBytes(body);
    }

    @Test
    void getDisplayNameReturnsChainPatrol() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("ChainPatrol");
    }

    @Test
    void getEndpointNameReturnsChainpatrol() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("chainpatrol");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://app.chainpatrol.io/api/v2/asset/check");
    }

    @Test
    void getMethodReturnsPost() {
        Assertions.assertThat(provider.getMethod()).isEqualTo(Method.POST);
    }

    @Test
    void getHeadersReturnsExpectedHeaders() {
        Map<String, String> headers = provider.getHeaders();
        Assertions.assertThat(headers).containsEntry("X-API-KEY", provider.getApiKey());
    }

    @Test
    void buildBodyReturnsExpectedFields() {
        Map<String, Object> body = provider.buildBody("https://example.com");
        Assertions.assertThat(body).containsEntry("content", "https://example.com");
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
        Assertions.assertThatThrownBy(() -> new ChainPatrol().validateConfig())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void acceptsApiProviderConfigurationWhenKeyIsPresent() {
        try (MockedStatic<APIKeyUtil> keys = Mockito.mockStatic(APIKeyUtil.class)) {
            Assertions.assertThatCode(() -> new ChainPatrol().validateConfig()).doesNotThrowAnyException();
            keys.verify(() -> APIKeyUtil.requireNonBlank(ArgumentMatchers.any(), ArgumentMatchers.anyString()));
        }
    }

    private static String readApiKey() throws ReflectiveOperationException {
        Field field = ChainPatrol.class.getDeclaredField("API_KEY");
        field.setAccessible(true);
        return (String) field.get(null);
    }

    @Test
    void interpretReturnsFailedOnInvalidJson() {
        LookupResult result = provider.interpret("not json".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsPhishingWhenStatusIsBlocked() {
        Map<String, Object> data = Map.of("status", "BLOCKED");
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.PHISHING);
    }

    @Test
    void interpretReturnsAllowedWhenStatusIsNotBlocked() {
        Map<String, Object> data = Map.of("status", "ALLOWED");
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenStatusIsNotAString() {
        Map<String, Object> data = Map.of("status", 1);
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenStatusIsMissing() {
        Map<String, Object> data = Map.of();
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }
}
