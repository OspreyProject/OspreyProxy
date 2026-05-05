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

    // The provider's greedy window capacity to simulate, in req/min
    private static final long SIMULATED_PROVIDER_WINDOW_PER_MIN = 1_980;

    // Seeded with the highest values observed in production so alerts only fire on new records
    private final AtomicLong globalHighestReqPerMin = new AtomicLong(594);
    private final AtomicLong globalHighestPeakReqPerSec = new AtomicLong(29);

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
            String name = entry.getKey();
            ProviderStats stats = entry.getValue();

            // Calculate elapsed time since last tick, with clamping to prevent extreme values from skewing rates
            long prevNanos = stats.lastTickNanos.getAndSet(nowNanos);
            double elapsedSecs = Math.clamp((nowNanos - prevNanos) / 1_000_000_000.0, 0.001, 5.0);

            long rawCount = stats.secondBucket.getAndSet(0);
            stats.minuteBucket.addAndGet(rawCount);

            // Calculate req/sec for this tick and update peak if needed
            long reqPerSec = (long) Math.ceil(rawCount / elapsedSecs);
            stats.peakReqPerSec.accumulateAndGet(reqPerSec, Math::max);

            // Simulate a greedy token bucket with the configured capacity and log if we see a deficit
            //noinspection ConstantMathCall
            long refillScaled = Math.round((SIMULATED_PROVIDER_WINDOW_PER_MIN / 60.0) * 100);
            long consumeScaled = reqPerSec * 100L;
            long capScaled = SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L;

            stats.simulatedTokenPoolScaled.updateAndGet(p ->
                    Math.max(Math.min(p + refillScaled, capScaled) - consumeScaled, 0)
            );

            double netDriftPerSec = (refillScaled - consumeScaled) / 100.0;

            if (netDriftPerSec < 0) {
                long minWindowNeeded = (long) Math.ceil(reqPerSec * 60.0);
                long prevHighest = stats.highestMinWindowNeeded.get();

                if (minWindowNeeded > prevHighest
                        && stats.highestMinWindowNeeded.compareAndSet(prevHighest, minWindowNeeded)) {
                    log.warn("[{}] Greedy window deficit - Consume vs refill: {}/sec | Min window needed: {}/min",
                            name, String.format("%.2f", netDriftPerSec), minWindowNeeded);
                }
            }
        }
    }

    @Scheduled(fixedDelay = 60_000)
    void tickPerMinute() {
        long highestReqThisMin = 0;
        long highestPeakThisMin = 0;
        String highestReqMinProvider = null;
        String highestPeakSecProvider = null;

        for (var entry : providerStats.entrySet()) {
            String name = entry.getKey();
            ProviderStats stats = entry.getValue();

            long reqThisMin = stats.minuteBucket.getAndSet(0);
            long peakThisMin = stats.peakReqPerSec.getAndSet(0);

            if (reqThisMin > highestReqThisMin) {
                highestReqThisMin = reqThisMin;
                highestReqMinProvider = name;
            }

            if (peakThisMin > highestPeakThisMin) {
                highestPeakThisMin = peakThisMin;
                highestPeakSecProvider = name;
            }
        }

        if (highestReqMinProvider != null && highestReqThisMin > globalHighestReqPerMin.get()) {
            globalHighestReqPerMin.set(highestReqThisMin);
            log.warn("[{}] New highest req/min across providers: {}", highestReqMinProvider, highestReqThisMin);
        }

        if (highestPeakSecProvider != null && highestPeakThisMin > globalHighestPeakReqPerSec.get()) {
            globalHighestPeakReqPerSec.set(highestPeakThisMin);
            log.warn("[{}] New highest req/sec across providers: {}", highestPeakSecProvider, highestPeakThisMin);
        }
    }

    private @NonNull Counter requestCounter(@NonNull String providerName) {
        return registry.counter("osprey.requests.total", Tags.of("provider", providerName));
    }

    private ProviderStats providerStats(@NonNull String providerName) {
        return providerStats.computeIfAbsent(providerName, str -> new ProviderStats());
    }

    private static final class ProviderStats {

        final AtomicLong secondBucket = new AtomicLong(0);
        final AtomicLong minuteBucket = new AtomicLong(0);
        final AtomicLong peakReqPerSec = new AtomicLong(0);

        // Initialised to startup time; the first tick will use the real elapsed duration
        final AtomicLong lastTickNanos = new AtomicLong(System.nanoTime());

        // Simulated token bucket scaled by 100 to allow fractional tokens without using floating-point arithmetic
        final AtomicLong simulatedTokenPoolScaled = new AtomicLong(SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L);
        final AtomicLong highestMinWindowNeeded = new AtomicLong(0);
    }
}
