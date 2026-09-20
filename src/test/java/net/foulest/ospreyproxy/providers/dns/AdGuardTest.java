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
import net.foulest.ospreyproxy.util.dns.DNSUtilTest;
import net.foulest.ospreyproxy.util.dns.DNSRecord;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;

class AdGuardTest {

    private final AdGuard provider = new AdGuard(Mockito.mock(CircuitBreakerService.class));

    @Test
    void getDisplayNameReturnsAdGuard() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("AdGuard");
    }

    @Test
    void getEndpointNameReturnsAdguardDns() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("adguard-dns");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://dns.adguard-dns.com/dns-query?dns=");
    }

    @Test
    void interpretReturnsFailedWhenRawBytesIsNull() {
        LookupResult result = provider.interpret(null, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsFailedWhenRawBytesIsEmpty() {
        LookupResult result = provider.interpret(new byte[0], (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretReturnsMaliciousWhenAnswerMatchesBlockedIp() {
        byte[] message = DNSUtilTest.messageWithAnswers("example.com", List.of(
                new DNSUtilTest.Answer(DNSRecord.A, 60, DNSUtilTest.ipv4("94.140.14.33"))
        ));

        LookupResult result = provider.interpret(message, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.MALICIOUS);
    }

    @Test
    void interpretReturnsAllowedWhenAnswerIsUnrelatedIp() {
        byte[] message = DNSUtilTest.messageWithAnswers("example.com", List.of(
                new DNSUtilTest.Answer(DNSRecord.A, 60, DNSUtilTest.ipv4("1.2.3.4"))
        ));

        LookupResult result = provider.interpret(message, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsAllowedWhenAnswerIsNotAnARecord() {
        byte[] message = DNSUtilTest.messageWithAnswers("example.com", List.of(
                new DNSUtilTest.Answer(DNSRecord.CNAME, 60, DNSUtilTest.encodeName("other.com"))
        ));

        LookupResult result = provider.interpret(message, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }
}
