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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class LocalListProviderTest {

    @Test
    void getDisplayNameReturnsDescriptorShortName() {
        LocalListProvider provider = new LocalListProvider(Descriptor.OPEN_PHISH);
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(Descriptor.OPEN_PHISH.getShortName());
    }

    @Test
    void getEndpointNameReturnsDescriptorEndpointName() {
        LocalListProvider provider = new LocalListProvider(Descriptor.OPEN_PHISH);
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(Descriptor.OPEN_PHISH.getEndpointName());
    }

    @Test
    void isEnabledReturnsTrue() {
        LocalListProvider provider = new LocalListProvider(Descriptor.OPEN_PHISH);
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(Descriptor.class)
    void getDisplayNameMatchesEveryDescriptor(Descriptor descriptor) {
        LocalListProvider provider = new LocalListProvider(descriptor);
        Assertions.assertThat(provider.getDisplayName()).isEqualTo(descriptor.getShortName());
    }

    @ParameterizedTest
    @EnumSource(Descriptor.class)
    void getEndpointNameMatchesEveryDescriptor(Descriptor descriptor) {
        LocalListProvider provider = new LocalListProvider(descriptor);
        Assertions.assertThat(provider.getEndpointName()).isEqualTo(descriptor.getEndpointName());
    }

    @ParameterizedTest
    @EnumSource(Descriptor.class)
    void isEnabledIsAlwaysTrue(Descriptor descriptor) {
        LocalListProvider provider = new LocalListProvider(descriptor);
        Assertions.assertThat(provider.isEnabled()).isTrue();
    }
}
