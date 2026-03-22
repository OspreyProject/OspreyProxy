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
package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Utility class for tracking and reporting per-provider request statistics.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class StatsUtil {

    // Request statistics per provider
    private static final class RequestStats {

        final AtomicLong totalRequestCount = new AtomicLong(0);
        final AtomicLong secondBucket = new AtomicLong(0);
        final AtomicLong minuteBucket = new AtomicLong(0);
        final AtomicLong peakReqPerSec = new AtomicLong(0);

        // Tracks the real wall-clock time of the last per-second tick so the scheduler
        // can compute an accurate per-second rate even when the task fires late (e.g., GC pause).
        // Initialised to startup time; the first tick will use the real elapsed duration.
        final AtomicReference<Long> lastTickNanos = new AtomicReference<>(System.nanoTime());

        // Greedy window simulation (scaled x100 to avoid floats in AtomicLong)
        final AtomicLong simulatedTokenPoolScaled = new AtomicLong(SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L);
        final AtomicLong highestMinWindowNeeded = new AtomicLong(0);
    }

    // The provider's greedy window capacity to simulate, in req/min
    private static final long SIMULATED_PROVIDER_WINDOW_PER_MIN = 1_980;

    // Map of every recorded stat per provider
    private static final ConcurrentHashMap<String, RequestStats> PROVIDER_STATS = new ConcurrentHashMap<>();

    // Global high-water marks across all providers (not per-provider, not combined)
    // Seeded with the highest values observed in production so alerts only fire on genuine new records
    private static final AtomicLong GLOBAL_HIGHEST_REQ_PER_MIN = new AtomicLong(594);
    private static final AtomicLong GLOBAL_HIGHEST_PEAK_REQ_PER_SEC = new AtomicLong(29);

    // Scheduler for periodic request statistics printing
    private static final ScheduledExecutorService REQUEST_STATS_SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "RequestStats");
        thread.setDaemon(true);
        return thread;
    });

    static {
        // Every ~second: drain secondBucket into minuteBucket, update peakReqPerSec, simulate greedy window.
        //
        // scheduleWithFixedDelay is used instead of scheduleAtFixedRate so that a delayed tick
        // (e.g., caused by a GC pause or thread starvation) does not cause the next tick to fire
        // immediately, which would drain a near-zero secondBucket and hide the spike.
        //
        // To handle the case where the task *does* fire late, we measure the real elapsed time
        // since the last tick and normalize the accumulated request count to a per-second rate.
        // This prevents a multi-second accumulation in secondBucket from appearing as a single
        // impossible spike (e.g., 50,000 req in one "second" when the task was delayed 2 seconds).
        REQUEST_STATS_SCHEDULER.scheduleWithFixedDelay(() -> {
            long nowNanos = System.nanoTime();

            for (Map.Entry<String, RequestStats> entry : PROVIDER_STATS.entrySet()) {
                String name = entry.getKey();
                RequestStats stats = entry.getValue();

                // Measures elapsed time since the last tick and update the timestamp atomically.
                // If two threads somehow raced here (they won't with single-thread scheduler), the
                // compareAndSet ensures only one wins and the other skips cleanly.
                long prevNanos = stats.lastTickNanos.get();
                double elapsedSecs = Math.min(Math.max((nowNanos - prevNanos) / 1_000_000_000.0, 0.001), 5.0);
                stats.lastTickNanos.compareAndSet(prevNanos, nowNanos);

                // Drains the raw count accumulated since the last tick
                long rawCount = stats.secondBucket.getAndSet(0);
                stats.minuteBucket.addAndGet(rawCount);

                // Normalizes to a per-second rate. Under normal operation elapsedSecs roughly equals 1.0,
                // so reqPerSec roughly equals rawCount. If the task fired late (elapsedSecs > 1), the rate
                // is scaled down to reflect the true throughput rather than an inflated spike.
                // We use Math.ceil so a single request in 1.1 seconds still counts as 1 req/sec,
                // not 0 (which would lose the event entirely).
                long reqPerSec = (long) Math.ceil(rawCount / elapsedSecs);

                stats.peakReqPerSec.accumulateAndGet(reqPerSec, Math::max);

                // Simulates the provider's greedy token pool using the normalized per-second rate.
                // refill rate = SIMULATED_PROVIDER_WINDOW_PER_MIN / 60.0 tokens/sec (scaled x100)
                // noinspection ConstantMathCall
                long refillScaled = Math.round((SIMULATED_PROVIDER_WINDOW_PER_MIN / 60.0) * 100);
                long consumeScaled = reqPerSec * 100L;
                long capScaled = SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L;

                // Apply refill then consume, clamping pool between 0 and cap
                stats.simulatedTokenPoolScaled.updateAndGet(p ->
                        Math.max(Math.min(p + refillScaled, capScaled) - consumeScaled, 0)
                );

                // Net drift this second: negative means we're consuming faster than the window refills
                double netDriftPerSec = (refillScaled - consumeScaled) / 100.0;

                if (netDriftPerSec < 0) {
                    // Minimum window (req/min) needed so refill rate >= consume rate: ceil(reqPerSec * 60)
                    long minWindowNeeded = (long) Math.ceil(reqPerSec * 60.0);
                    long prevHighest = stats.highestMinWindowNeeded.get();

                    if (minWindowNeeded > prevHighest && stats.highestMinWindowNeeded.compareAndSet(prevHighest, minWindowNeeded)) {
                        log.warn("[{}] Greedy window deficit - Consume vs refill: {}/sec | Min window needed: {}/min",
                                name, String.format("%.2f", netDriftPerSec), minWindowNeeded);
                    }
                }
            }
        }, 1, 1, TimeUnit.SECONDS);

        // Every 60 seconds: find the single highest req/min and req/sec across all providers,
        // then alert only when either sets a new global record.
        // This reflects the peak load on any one provider, not a combined total.
        REQUEST_STATS_SCHEDULER.scheduleWithFixedDelay(() -> {
            long highestReqThisMin = 0;
            long highestPeakThisMin = 0;
            String highestReqMinProvider = null;
            String highestPeakSecProvider = null;

            for (Map.Entry<String, RequestStats> entry : PROVIDER_STATS.entrySet()) {
                String name = entry.getKey();
                RequestStats stats = entry.getValue();

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

            if (highestReqMinProvider != null && highestReqThisMin > GLOBAL_HIGHEST_REQ_PER_MIN.get()) {
                GLOBAL_HIGHEST_REQ_PER_MIN.set(highestReqThisMin);
                log.warn("[{}] New highest req/min across providers: {}", highestReqMinProvider, highestReqThisMin);
            }

            if (highestPeakSecProvider != null && highestPeakThisMin > GLOBAL_HIGHEST_PEAK_REQ_PER_SEC.get()) {
                GLOBAL_HIGHEST_PEAK_REQ_PER_SEC.set(highestPeakThisMin);
                log.warn("[{}] New highest req/sec across providers: {}", highestPeakSecProvider, highestPeakThisMin);
            }
        }, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * Records one request for the given provider, incrementing the total request
     * count and the current-second bucket used by the scheduler.
     *
     * @param providerName The provider name to record the request for.
     */
    public static void recordRequest(@NonNull String providerName) {
        RequestStats stats = PROVIDER_STATS.computeIfAbsent(providerName, k -> new RequestStats());
        stats.totalRequestCount.incrementAndGet();
        stats.secondBucket.incrementAndGet();
    }
}
