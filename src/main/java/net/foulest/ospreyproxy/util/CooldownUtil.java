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
 * Utility class for managing cooldowns of providers after receiving 429 or 5xx responses.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CooldownUtil {

    // Deadline nanos per provider
    private static final ConcurrentHashMap<String, Long> COOLDOWN_DEADLINES = new ConcurrentHashMap<>();

    private static final long COOLDOWN_NANOS = 1_000_000_000L;
    // Cooldown durations in nanoseconds

    /**
     * Checks if the given provider is currently cooling down.
     *
     * @param providerName The display name of the provider to check.
     * @return {@code true} if the provider is cooling down, {@code false} otherwise.
     */
    public static boolean isCoolingDown(@NonNull String providerName) {
        Long deadline = COOLDOWN_DEADLINES.get(providerName);
        return deadline != null && System.nanoTime() < deadline;
    }

    /**
     * Triggers a cooldown for the given provider for the specified duration.
     *
     * @param providerName The display name of the provider to trigger cooldown for.
     * @param durationNanos The duration of the cooldown in nanoseconds.
     */
    public static void triggerCooldown(@NonNull String providerName) {
        long deadline = System.nanoTime() + COOLDOWN_NANOS;
        COOLDOWN_DEADLINES.put(providerName, deadline);
        log.warn("[{}] Upstream returned 429; provider cooling down for 1 second", providerName);
    }
}
