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
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Map;

class PrecisionSecTest {

    private final PrecisionSec provider = new PrecisionSec();

    private static byte[] bytes(Map<String, Object> body) {
        return JacksonUtil.MAPPER.writeValueAsBytes(body);
    }

    @Test
    void getDisplayNameReturnsPrecisionSec() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("PrecisionSec");
    }

    @Test
    void getEndpointNameReturnsPrecisionsec() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("precisionsec");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://api.precisionsec.com/check_domain/");
    }

    @Test
    void getHeadersReturnsExpectedHeaders() {
        Map<String, String> headers = provider.getHeaders();
        Assertions.assertThat(headers).containsEntry("API-Key", provider.getApiKey());
    }

    @Test
    void isStripToHostReturnsTrue() {
        Assertions.assertThat(provider.isStripToHost()).isTrue();
    }

    @Test
    void buildRequestUrlAppendsUrlToApiUrl() {
        Assertions.assertThat(provider.buildRequestUrl("example.com"))
                .isEqualTo(provider.getApiUrl() + "example.com");
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

    private static String readApiKey() throws ReflectiveOperationException {
        Field field = PrecisionSec.class.getDeclaredField("API_KEY");
        field.setAccessible(true);
        return (String) field.get(null);
    }

    @Test
    void interpretReturnsFailedOnInvalidJson() {
        LookupResult result = provider.interpret("not json".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsMaliciousWhenResultIsMalicious() {
        Map<String, Object> data = Map.of("result", "Malicious");
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.MALICIOUS);
    }

    @Test
    void interpretReturnsAllowedWhenResultIsSomethingElse() {
        Map<String, Object> data = Map.of("result", "Clean");
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenResultIsMissing() {
        Map<String, Object> data = Map.of();
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }
}
