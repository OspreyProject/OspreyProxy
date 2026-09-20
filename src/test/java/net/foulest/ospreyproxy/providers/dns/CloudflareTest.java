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
package net.foulest.ospreyproxy.providers.dns;

import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.services.CircuitBreakerService;
import net.foulest.ospreyproxy.util.dns.DNSFormat;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;

class CloudflareTest {

    private final Cloudflare provider = new Cloudflare(Mockito.mock(CircuitBreakerService.class));

    @Test
    void getDisplayNameReturnsCloudflare() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("Cloudflare");
    }

    @Test
    void getEndpointNameReturnsCloudflare() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("cloudflare");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://security.cloudflare-dns.com/dns-query?name=");
    }

    @Test
    void getDnsFormatReturnsNameJson() {
        Assertions.assertThat(provider.getDnsFormat()).isEqualTo(DNSFormat.NAME_JSON);
    }

    @Test
    void interpretReturnsFailedWhenJsonResponseIsNull() {
        LookupResult result = provider.interpret(null, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsFailedWhenJsonResponseIsEmpty() {
        LookupResult result = provider.interpret(null, Map.of());
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsMaliciousWhenCommentIsStringContainingCensored() {
        Map<String, Object> json = Map.of("Comment", "EDE(16): Censored, this domain is blocked");
        LookupResult result = provider.interpret(null, json);
        Assertions.assertThat(result).isEqualTo(LookupResult.MALICIOUS);
    }

    @Test
    void interpretReturnsMaliciousWhenCommentIsListContainingCensored() {
        Map<String, Object> json = Map.of("Comment", List.of("Response from upstream", "EDE(16): Censored"));
        LookupResult result = provider.interpret(null, json);
        Assertions.assertThat(result).isEqualTo(LookupResult.MALICIOUS);
    }

    @Test
    void interpretReturnsAllowedWhenCommentDoesNotContainCensored() {
        Map<String, Object> json = Map.of("Comment", "Response from upstream resolver");
        LookupResult result = provider.interpret(null, json);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenCommentIsMissing() {
        Map<String, Object> json = Map.of("Status", 0);
        LookupResult result = provider.interpret(null, json);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenCommentIsUnexpectedType() {
        Map<String, Object> json = Map.of("Comment", 42);
        LookupResult result = provider.interpret(null, json);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }
}
