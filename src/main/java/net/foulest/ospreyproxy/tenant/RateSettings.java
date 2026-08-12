package net.foulest.ospreyproxy.tenant;

import org.jspecify.annotations.NonNull;

/**
 * The resolved rate budget for a tenant, kept immutable so it can be compared cheaply on reload.
 *
 * @param burstCapacity Burst token capacity.
 * @param burstWindowSeconds Burst refill window, in seconds.
 * @param sustainedCapacity Sustained token capacity.
 * @param sustainedWindowSeconds Sustained refill window, in seconds.
 */
public record RateSettings(long burstCapacity, long burstWindowSeconds,
                           long sustainedCapacity, long sustainedWindowSeconds) {

    @NonNull
    public RateSettings withBurstCapacity(long value) {
        return new RateSettings(value, burstWindowSeconds, sustainedCapacity, sustainedWindowSeconds);
    }

    @NonNull
    public RateSettings withBurstWindowSeconds(long value) {
        return new RateSettings(burstCapacity, value, sustainedCapacity, sustainedWindowSeconds);
    }

    @NonNull
    public RateSettings withSustainedCapacity(long value) {
        return new RateSettings(burstCapacity, burstWindowSeconds, value, sustainedWindowSeconds);
    }

    @NonNull
    public RateSettings withSustainedWindowSeconds(long value) {
        return new RateSettings(burstCapacity, burstWindowSeconds, sustainedCapacity, value);
    }
}
