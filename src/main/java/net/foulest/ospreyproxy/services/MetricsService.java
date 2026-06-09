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
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for recording and analyzing request metrics.
 */
@Slf4j
@Service
@EnableScheduling
@RequiredArgsConstructor
public class MetricsService {

    // Per-provider sliding-window state; lazily created on first recordRequest() call
    private final ConcurrentHashMap<String, ProviderStats> providerStats = new ConcurrentHashMap<>();

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
        providerStats(providerName).secondBucket.incrementAndGet();
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

    @Scheduled(fixedDelay = 1_000)
    void tickPerSecond() {
        long nowNanos = System.nanoTime();

        for (var entry : providerStats.entrySet()) {
            ProviderStats stats = entry.getValue();

            // Calculate elapsed time since last tick, with clamping to prevent extreme values from skewing rates
            long prevNanos = stats.lastTickNanos.getAndSet(nowNanos);
            double elapsedSecs = Math.clamp((nowNanos - prevNanos) / 1_000_000_000.0, 0.001, 5.0);

            long rawCount = stats.secondBucket.getAndSet(0);
            stats.minuteBucket.addAndGet(rawCount);

            // Calculate req/sec for this tick and update peak if needed
            long reqPerSec = (long) Math.ceil(rawCount / elapsedSecs);
            stats.peakReqPerSec.accumulateAndGet(reqPerSec, Math::max);
        }
    }

    private @NonNull Counter requestCounter(@NonNull String providerName) {
        return registry.counter("osprey.requests.total", Tags.of("provider", providerName));
    }

    private ProviderStats providerStats(@NonNull String providerName) {
        return providerStats.computeIfAbsent(providerName, str -> new ProviderStats());
    }

    private static final class ProviderStats {

        private final AtomicLong secondBucket = new AtomicLong(0);
        private final AtomicLong minuteBucket = new AtomicLong(0);
        private final AtomicLong peakReqPerSec = new AtomicLong(0);

        // Initialised to startup time; the first tick will use the real elapsed duration
        private final AtomicLong lastTickNanos = new AtomicLong(System.nanoTime());
    }
}
