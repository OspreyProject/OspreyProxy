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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Per-provider circuit breaker.
 * <p>
 * Failure counting resets whenever a request succeeds, so a brief outage
 * does not permanently inflate the failure counter.
 * <p>
 * Thread-safety: all mutable state is held in {@link AtomicInteger} /
 * {@link AtomicLong} fields inside a per-provider {@link ProviderState} record.
 * The HALF_OPEN probe is coordinated with a single CAS so exactly one virtual
 * thread gets to probe at a time.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CircuitBreakerUtil {

    // Number of consecutive failures required to open the circuit
    private static final int FAILURE_THRESHOLD = 5;

    // How long the circuit stays OPEN before allowing a probe, in milliseconds
    private static final long COOLDOWN_MS = 30_000L;

    private enum State {
        CLOSED, OPEN, HALF_OPEN
    }

    /**
     * All mutable state for one provider's circuit breaker.
     */
    private static final class ProviderState {

        // Current state, stored as ordinal to allow atomic CAS via AtomicInteger
        final AtomicInteger state = new AtomicInteger(State.CLOSED.ordinal());

        // Consecutive failure counter; reset to 0 on any success
        final AtomicInteger failureCount = new AtomicInteger(0);

        // Wall-clock time (ms) at which the circuit was opened; 0 when CLOSED
        final AtomicLong openedAtMs = new AtomicLong(0);
    }

    // One ProviderState per provider name, created lazily on first use
    private static final ConcurrentHashMap<String, ProviderState> STATES = new ConcurrentHashMap<>();

    /**
     * Returns the {@link ProviderState} for {@code providerName}, creating it if absent.
     *
     * @param providerName The provider name to get the state for.
     * @return The {@link ProviderState} for the given provider name.
     */
    private static @NonNull ProviderState stateFor(@NonNull String providerName) {
        return STATES.computeIfAbsent(providerName, k -> new ProviderState());
    }

    /**
     * Returns {@code true} if the circuit is OPEN and the cooldown has not yet elapsed,
     * meaning the caller should reject the request immediately without attempting
     * an upstream call.
     * <p>
     * When the cooldown <em>has</em> elapsed, exactly one caller will transition the
     * circuit to HALF_OPEN (via CAS) and be allowed through as a probe. All other
     * concurrent callers still see the circuit as open and are rejected until the
     * probe result is recorded via {@link #recordSuccess} or {@link #recordFailure}.
     *
     * @param providerName The provider name to check.
     * @return {@code true} if the request should be short-circuited (rejected fast).
     */
    public static boolean isOpen(@NonNull String providerName) {
        ProviderState ps = stateFor(providerName);
        int state = ps.state.get();
        int open = State.OPEN.ordinal();
        int halfOpen = State.HALF_OPEN.ordinal();
        int closed = State.CLOSED.ordinal();

        if (state == closed) {
            return false;
        }

        if (state == open) {
            long elapsed = System.currentTimeMillis() - ps.openedAtMs.get();

            // Cooldown has elapsed; try to transition to HALF_OPEN so one probe
            // request gets through. Only one thread wins the CAS; the rest continue
            // to see the circuit as open. The winner is allowed through.
            if (elapsed >= COOLDOWN_MS && ps.state.compareAndSet(open, halfOpen)) {
                log.warn("[{}] Circuit breaker HALF_OPEN; allowing probe request", providerName);
                return false;
            }

            // Either cooldown hasn't elapsed, or another thread already won the CAS
            return true;
        }

        // HALF_OPEN: the probe is in flight; all other requests are rejected.
        // The probe thread set state to HALF_OPEN and returned false above.
        // Every other thread arriving here sees HALF_OPEN and is blocked.
        return state == halfOpen;
    }

    /**
     * Records a successful upstream response. Resets the failure counter and,
     * if the circuit was HALF_OPEN, closes it.
     *
     * @param providerName The provider name to record the success for.
     */
    public static void recordSuccess(@NonNull String providerName) {
        ProviderState ps = stateFor(providerName);
        int closed = State.CLOSED.ordinal();
        int halfOpen = State.HALF_OPEN.ordinal();
        int prev = ps.state.getAndSet(closed);

        ps.failureCount.set(0);
        ps.openedAtMs.set(0);

        if (prev == halfOpen) {
            log.warn("[{}] Circuit breaker CLOSED; probe succeeded", providerName);
        }
    }

    /**
     * Records a failed upstream request (timeout, connection error, or 5xx).
     * Increments the failure counter and opens the circuit if the threshold is reached.
     * If the circuit was HALF_OPEN, the probe failed; reopen immediately.
     *
     * @param providerName The provider name to record the failure for.
     */
    public static void recordFailure(@NonNull String providerName) {
        ProviderState ps = stateFor(providerName);
        int open = State.OPEN.ordinal();
        int halfOpen = State.HALF_OPEN.ordinal();
        int closed = State.CLOSED.ordinal();

        if (ps.state.get() == halfOpen) {
            // Probe failed; reopen with a fresh cooldown
            ps.openedAtMs.set(System.currentTimeMillis());
            ps.state.set(open);
            log.warn("[{}] Circuit breaker OPEN; probe failed, cooldown reset ({}s)", providerName, COOLDOWN_MS / 1000);
            return;
        }

        int failures = ps.failureCount.incrementAndGet();

        if (failures >= FAILURE_THRESHOLD && ps.state.compareAndSet(closed, open)) {
            ps.openedAtMs.set(System.currentTimeMillis());
            log.warn("[{}] Circuit breaker OPEN; {} consecutive failures, cooldown {}s", providerName, failures, COOLDOWN_MS / 1000);
        }
    }
}
