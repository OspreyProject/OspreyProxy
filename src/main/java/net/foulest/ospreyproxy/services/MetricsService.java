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
package net.foulest.ospreyproxy.services;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

/**
 * Service for recording and analyzing request metrics.
 */
@Service
@RequiredArgsConstructor
public class MetricsService {

    // Micrometer registry injected by Spring Boot autoconfiguration
    private final MeterRegistry registry;

    /**
     * Records a request for the given provider, updating both the total count and the current second's bucket
     * for rate calculations.
     *
     * @param providerName The name of the provider handling the request,
     *                     used for tagging metrics and tracking per-provider stats.
     */
    public void recordRequest(@NonNull String providerName) {
        requestCounter(providerName).increment();
    }

    /**
     * Records a cache hit, incrementing the appropriate counter in the registry. This method is called by
     * providers when they successfully serve a request from cache, allowing us to track cache effectiveness over time.
     */
    public void recordCacheHit() {
        registry.counter("osprey.cache.hits").increment();
    }

    /**
     * Records a cache miss, incrementing the appropriate counter in the registry. This method is called by
     * providers when they fail to serve a request from cache, allowing us to track cache effectiveness over time.
     */
    public void recordCacheMiss() {
        registry.counter("osprey.cache.misses").increment();
    }

    private @NonNull Counter requestCounter(@NonNull String providerName) {
        return registry.counter("osprey.requests.total", Tags.of("provider", providerName));
    }
}
