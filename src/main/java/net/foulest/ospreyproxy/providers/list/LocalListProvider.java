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
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.services.MetricsService;
import net.foulest.ospreyproxy.util.list.Descriptor;
import net.foulest.ospreyproxy.util.list.LocalListUtil;
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
@Slf4j
@RequiredArgsConstructor
public class LocalListProvider extends AbstractProvider {

    private final Descriptor descriptor;
    private final MetricsService metricsService;

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

    @Override
    public final @NonNull LookupResult cachedLookup(@NonNull String lookupStr) {
        LookupResult cached = getCachedResult(lookupStr);

        if (cached != null) {
            metricsService.recordCacheHit();
            return cached;
        }

        metricsService.recordCacheMiss();
        LookupResult result = LocalListUtil.lookupHost(descriptor, lookupStr);
        putCachedResult(lookupStr, result);
        return result;
    }
}
