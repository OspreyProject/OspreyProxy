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
package net.foulest.ospreyproxy.util.stats;

import lombok.Getter;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@Getter
final class RequestStats {

    AtomicLong totalRequestCount = new AtomicLong(0);
    AtomicLong secondBucket = new AtomicLong(0);
    AtomicLong minuteBucket = new AtomicLong(0);
    AtomicLong peakReqPerSec = new AtomicLong(0);

    // Tracks the real wall-clock time of the last per-second tick so the scheduler
    // can compute an accurate per-second rate even when the task fires late (e.g., GC pause).
    // Initialised to startup time; the first tick will use the real elapsed duration.
    AtomicReference<Long> lastTickNanos = new AtomicReference<>(System.nanoTime());

    // Greedy window simulation (scaled x100 to avoid floats in AtomicLong)
    AtomicLong simulatedTokenPoolScaled = new AtomicLong(StatsUtil.SIMULATED_PROVIDER_WINDOW_PER_MIN * 100L);
    AtomicLong highestMinWindowNeeded = new AtomicLong(0);
}
