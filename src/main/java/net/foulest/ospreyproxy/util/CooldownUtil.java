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
@SuppressWarnings("MissingJavadoc")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CooldownUtil {

    // Deadline nanos per provider
    private static final ConcurrentHashMap<String, Long> COOLDOWN_DEADLINES = new ConcurrentHashMap<>();

    // Cooldown durations in nanoseconds
    public static final long COOLDOWN_429 = 1_000_000_000L;
    public static final long COOLDOWN_5XX = 3_000_000_000L;

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
    public static void triggerCooldown(@NonNull String providerName, long durationNanos) {
        long deadline = System.nanoTime() + durationNanos;
        COOLDOWN_DEADLINES.put(providerName, deadline);
        log.warn("[{}] Provider cooling down for {}ms", providerName, durationNanos / 1_000_000);
    }
}
