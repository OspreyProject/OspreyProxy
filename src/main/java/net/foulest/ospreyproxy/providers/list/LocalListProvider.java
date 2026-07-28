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

import lombok.RequiredArgsConstructor;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.util.list.Descriptor;
import org.jspecify.annotations.NonNull;

/**
 * Thin {@link net.foulest.ospreyproxy.providers.Provider} wrapper around a {@link Descriptor}.
 * <p>
 * Allows local lists to participate in the standard routing pipeline (rate limiting,
 * URL validation, endpoint dispatch) without any changes to
 * {@link net.foulest.ospreyproxy.ProxyHandler}.
 * <p>
 * One bean is registered per {@link Descriptor} constant via {@link LocalListProviderConfig}.
 */
@RequiredArgsConstructor
public class LocalListProvider extends AbstractProvider {

    private final Descriptor descriptor;

    @Override
    public @NonNull String getDisplayName() {
        return descriptor.getShortName();
    }

    @Override
    public @NonNull String getEndpointName() {
        return descriptor.getEndpointName();
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
