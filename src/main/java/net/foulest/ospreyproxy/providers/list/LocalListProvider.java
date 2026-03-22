/*
 * OspreyProxy - backend code for our proxy server using Spring MVC.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
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
import org.apache.hc.core5.http.Method;
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
        return descriptor.shortName;
    }

    @Override
    public @NonNull String getShortName() {
        return descriptor.endpointName;
    }

    @Override
    public @NonNull String getEndpointName() {
        return descriptor.endpointName;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public @NonNull Method getMethod() {
        return Method.GET;
    }
}
