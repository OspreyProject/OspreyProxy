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
package net.foulest.ospreyproxy.providers.list;

import net.foulest.ospreyproxy.util.list.Descriptor;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class LocalListProviderConfigTest {

    private final LocalListProviderConfig config = new LocalListProviderConfig();

    @Test
    void openPhishProviderUsesOpenPhishDescriptor() {
        LocalListProvider provider = config.openPhishProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.OPEN_PHISH.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.OPEN_PHISH.getShortName());
    }

    @Test
    void acomicsProviderUsesAcomicsDescriptor() {
        LocalListProvider provider = config.acomicsProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.ACOMICS.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.ACOMICS.getShortName());
    }

    @Test
    void phishuntProviderUsesPhishuntIoDescriptor() {
        LocalListProvider provider = config.phishuntProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.PHISHUNT_IO.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.PHISHUNT_IO.getShortName());
    }

    @Test
    void redFlagDomainsProviderUsesRedFlagDomainsDescriptor() {
        LocalListProvider provider = config.redFlagDomainsProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.RED_FLAG_DOMAINS.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.RED_FLAG_DOMAINS.getShortName());
    }

    @Test
    void sinkingYachtsProviderUsesSinkingYachtsDescriptor() {
        LocalListProvider provider = config.sinkingYachtsProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.SINKING_YACHTS.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.SINKING_YACHTS.getShortName());
    }

    @Test
    void threatfoxProviderUsesThreatfoxDescriptor() {
        LocalListProvider provider = config.threatfoxProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.THREATFOX.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.THREATFOX.getShortName());
    }

    @Test
    void urlhausProviderUsesUrlhausDescriptor() {
        LocalListProvider provider = config.urlhausProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.URLHAUS.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.URLHAUS.getShortName());
    }

    @Test
    void validinProviderUsesValidinDescriptor() {
        LocalListProvider provider = config.validinProvider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.VALIDIN.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.VALIDIN.getShortName());
    }

    @Test
    void aa419ProviderUsesAa419Descriptor() {
        LocalListProvider provider = config.aa419Provider();
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.AA419.getEndpointName());
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.AA419.getShortName());
    }
}
