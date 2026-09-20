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
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.apache.hc.core5.http.Method;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

class IZOOlogicTest {

    private final IZOOlogic provider = new IZOOlogic();

    private static byte[] bytes(Map<String, Object> body) {
        return JacksonUtil.MAPPER.writeValueAsBytes(body);
    }

    @Test
    void getDisplayNameReturnsIZOOlogic() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("iZOOlogic");
    }

    @Test
    void getEndpointNameReturnsIzoologic() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("izoologic");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://opencti.izoolabs.com/api/CTI/GetUrlVerdict");
    }

    @Test
    void getMethodReturnsPost() {
        Assertions.assertThat(provider.getMethod()).isEqualTo(Method.POST);
    }

    @Test
    void buildBodyReturnsExpectedFields() {
        Map<String, Object> body = provider.buildBody("https://example.com");
        Assertions.assertThat(body).containsEntry("url", "https://example.com");
    }

    @Test
    void interpretReturnsFailedOnInvalidJson() {
        LookupResult result = provider.interpret("not json".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsMaliciousWhenResultIsMaliciousOrPhishingUrl() {
        Map<String, Object> data = Map.of("result", "Malicious or Phishing Url");
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
