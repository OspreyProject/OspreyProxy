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
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Map;

class Quad9Test {

    private final Quad9 provider = new Quad9(Mockito.mock(CircuitBreakerService.class));

    @Test
    void getDisplayNameReturnsQuad9() {
        Assertions.assertThat(provider.getDisplayName()).isEqualTo("Quad9");
    }

    @Test
    void getEndpointNameReturnsQuad9() {
        Assertions.assertThat(provider.getEndpointName()).isEqualTo("quad9");
    }

    @Test
    void isEnabledReturnsTrue() {
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @Test
    void getApiUrlReturnsExpectedUrl() {
        Assertions.assertThat(provider.getApiUrl()).isEqualTo("https://dns.quad9.net/dns-query?dns=");
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
    void interpretReturnsAllowedWhenRawBytesIsShorterThanFourBytes() {
        LookupResult result = provider.interpret(new byte[]{0x00, 0x00, 0x00}, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }

    @Test
    void interpretReturnsMaliciousWhenFourthByteIndicatesBlocked() {
        LookupResult result = provider.interpret(new byte[]{0x00, 0x00, 0x00, 0x03}, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.MALICIOUS);
    }

    @Test
    void interpretReturnsAllowedWhenFourthByteDoesNotIndicateBlocked() {
        LookupResult result = provider.interpret(new byte[]{0x00, 0x00, 0x00, 0x00}, (Map<String, Object>) null);
        Assertions.assertThat(result).isEqualTo(LookupResult.ALLOWED);
    }
}
