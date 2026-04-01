/*
 * OspreyProxy - backend code for our proxy server using Spring MVC.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 * ...license header...
 */
package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks per-provider upstream 429 cooldowns.
 * <p>
 * When an upstream API provider responds with HTTP 429 (Too Many Requests),
 * the provider is placed into a 1-second cooldown. All requests to that provider
 * during the cooldown window are immediately rejected with 429, preventing
 * further upstream hammering while the provider recovers.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CooldownUtil {

    // Deadline nanos per provider — present and in the future means cooling down.
    private static final ConcurrentHashMap<String, Long> COOLDOWN_DEADLINES = new ConcurrentHashMap<>();

    // Cooldown duration in nanoseconds (1 second)
    private static final long COOLDOWN_NANOS = 1_000_000_000L;

    /**
     * Returns {@code true} if the given provider is currently in a 429 cooldown.
     *
     * @param providerName The display name of the provider to check.
     * @return {@code true} if requests should be short-circuited with 429.
     */
    public static boolean isCoolingDown(@NonNull String providerName) {
        Long deadline = COOLDOWN_DEADLINES.get(providerName);
        return deadline != null && System.nanoTime() < deadline;
    }

    /**
     * Arms a 1-second cooldown for the given provider. If a cooldown is already
     * active, the deadline is extended from now (not stacked), so repeated 429s
     * each add a fresh 1-second window rather than compounding indefinitely.
     *
     * @param providerName The display name of the provider to cool down.
     */
    public static void triggerCooldown(@NonNull String providerName) {
        long deadline = System.nanoTime() + COOLDOWN_NANOS;
        COOLDOWN_DEADLINES.put(providerName, deadline);
        log.warn("[{}] Upstream returned 429; provider cooling down for 1 second", providerName);
    }
}
