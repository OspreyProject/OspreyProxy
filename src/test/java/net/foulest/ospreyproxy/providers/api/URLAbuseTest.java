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
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

class URLAbuseTest {

    private final URLAbuse provider = new URLAbuse();

    private static byte[] bytes(Map<String, Object> body) {
        return JacksonUtil.MAPPER.writeValueAsBytes(body);
    }

    @Test
    void getDisplayNameReturnsURLAbuse() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("URLAbuse");
    }

    @Test
    void getEndpointNameReturnsUrlabuse() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("urlabuse");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://dbl.urlabuse.com/lookup?rd=");
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

    @Test
    void interpretReturnsFailedOnInvalidJson() {
        LookupResult result = provider.interpret("not json".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsMaliciousWhenAttrIsBlacklisted() {
        Map<String, Object> data = Map.of("attr", "BLACKLISTED");
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.MALICIOUS);
    }

    @Test
    void interpretReturnsAllowedWhenAttrIsSomethingElse() {
        Map<String, Object> data = Map.of("attr", "CLEAN");
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenAttrIsMissing() {
        Map<String, Object> data = Map.of();
        LookupResult result = provider.interpret(bytes(data), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }
}
