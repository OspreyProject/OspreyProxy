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
        final AtomicLong highestReqPerMin = new AtomicLong(0);
        final AtomicLong highestPeakReqPerSec = new AtomicLong(0);

        // Greedy window simulation (scaled x100 to avoid floats in AtomicLong)
        final AtomicLong simulatedTokenPoolScaled = new AtomicLong(SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L);
        final AtomicLong highestMinWindowNeeded = new AtomicLong(0);
    }

    // The provider's greedy window capacity to simulate, in req/min
    private static final long SIMULATED_PROVIDER_WINDOW_PER_MIN = 1_740;

    // Map of every recorded stat per provider
    private static final ConcurrentHashMap<String, RequestStats> PROVIDER_STATS = new ConcurrentHashMap<>();

    // Scheduler for periodic request statistics printing
    private static final ScheduledExecutorService REQUEST_STATS_SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "RequestStats");
        thread.setDaemon(true);
        return thread;
    });

    static {
        // Every second: drain secondBucket into minuteBucket, update peakReqPerSec, simulate greedy window
        REQUEST_STATS_SCHEDULER.scheduleAtFixedRate(() -> {
            for (Map.Entry<String, RequestStats> entry : PROVIDER_STATS.entrySet()) {
                String name = entry.getKey();
                RequestStats stats = entry.getValue();
                long reqThisSec = stats.secondBucket.getAndSet(0);
                stats.minuteBucket.addAndGet(reqThisSec);

                long current = stats.peakReqPerSec.get();
                if (reqThisSec > current) {
                    stats.peakReqPerSec.set(reqThisSec);
                }

                // Simulate the provider's greedy token pool:
                // refill rate = SIMULATED_PROVIDER_WINDOW_PER_MIN / 60.0 tokens/sec (scaled x100)
                long refillScaled = 2900;
                long consumeScaled = reqThisSec * 100L;
                long capScaled = SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L;

                // Apply refill then consume, clamping pool between 0 and cap
                long pool = stats.simulatedTokenPoolScaled.get();
                pool = Math.min(pool + refillScaled, capScaled);
                pool = Math.max(pool - consumeScaled, 0);
                stats.simulatedTokenPoolScaled.set(pool);

                // Net drift this second: negative means we're consuming faster than the window refills
                double netDriftPerSec = (refillScaled - consumeScaled) / 100.0;

                if (netDriftPerSec < 0) {
                    // Minimum window (req/min) needed so refill rate >= consume rate: ceil(reqThisSec * 60)
                    long minWindowNeeded = (long) Math.ceil(reqThisSec * 60.0);

                    if (minWindowNeeded > stats.highestMinWindowNeeded.get()) {
                        stats.highestMinWindowNeeded.set(minWindowNeeded);
                        log.warn("[{}] Greedy window deficit — Consume vs refill: {}/sec | Min window needed: {}/min",
                                name, String.format("%.2f", netDriftPerSec), minWindowNeeded);
                    }
                }
            }
        }, 1, 1, TimeUnit.SECONDS);

        // Every 60 seconds: check per-provider highs and log only when a new recordRequest is set
        REQUEST_STATS_SCHEDULER.scheduleAtFixedRate(() -> PROVIDER_STATS.forEach((name, stats) -> {
            long reqThisMin = stats.minuteBucket.getAndSet(0);
            long peakThisMin = stats.peakReqPerSec.getAndSet(0);

            if (reqThisMin > stats.highestReqPerMin.get()) {
                stats.highestReqPerMin.set(reqThisMin);
                log.warn("[{}] New highest req/min: {}", name, reqThisMin);
            }

            if (peakThisMin > stats.highestPeakReqPerSec.get()) {
                stats.highestPeakReqPerSec.set(peakThisMin);
                log.warn("[{}] New highest req/sec: {}", name, peakThisMin);
            }
        }), 60, 60, TimeUnit.SECONDS);
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
