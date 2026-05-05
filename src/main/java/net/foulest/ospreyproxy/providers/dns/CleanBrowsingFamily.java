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
package net.foulest.ospreyproxy.providers.dns;

import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.providers.AbstractDNSProvider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.services.CircuitBreakerService;
import net.foulest.ospreyproxy.services.MetricsService;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Provider implementation for CleanBrowsing Family DNS.
 */
@Slf4j
@Component
public class CleanBrowsingFamily extends AbstractDNSProvider {

    private static final String API_URL = "https://doh.cleanbrowsing.org/doh/family-filter/?dns=";
    private static final int REFUSED_FLAGS = 131; // RCODE 5 (REFUSED) in the flags byte

    /**
     * Constructor for the provider.
     *
     * @param metricsService The metrics service to use for recording metrics.
     * @param circuitBreakerService The circuit breaker service to use for handling failures.
     */
    public CleanBrowsingFamily(MetricsService metricsService, CircuitBreakerService circuitBreakerService) {
        super(metricsService, circuitBreakerService);
    }

    @Override
    public @NonNull String getDisplayName() {
        return "CleanBrowsing Family";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "cleanbrowsing-family";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    protected LookupResult interpret(byte @Nullable [] rawBytes,
                                     @Nullable Map<String, Object> jsonResponse) {
        if (rawBytes == null || rawBytes.length == 0) {
            return LookupResult.FAILED;
        }

        boolean blocked = rawBytes.length >= 4 && (rawBytes[3] & 0xFF) == REFUSED_FLAGS;
        return blocked ? LookupResult.ADULT_CONTENT : LookupResult.ALLOWED;
    }
}
