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

    /**
     * Returns a copy of this settings object with the burst capacity replaced.
     *
     * @param value New burst token capacity.
     * @return A new instance with the updated burst capacity.
     */
    @NonNull
    public RateSettings withBurstCapacity(long value) {
        return new RateSettings(value, burstWindowSeconds, sustainedCapacity, sustainedWindowSeconds);
    }

    /**
     * Returns a copy of this settings object with the burst refill window replaced.
     *
     * @param value New burst refill window, in seconds.
     * @return A new instance with the updated burst window.
     */
    @NonNull
    public RateSettings withBurstWindowSeconds(long value) {
        return new RateSettings(burstCapacity, value, sustainedCapacity, sustainedWindowSeconds);
    }

    /**
     * Returns a copy of this settings object with the sustained capacity replaced.
     *
     * @param value New sustained token capacity.
     * @return A new instance with the updated sustained capacity.
     */
    @NonNull
    public RateSettings withSustainedCapacity(long value) {
        return new RateSettings(burstCapacity, burstWindowSeconds, value, sustainedWindowSeconds);
    }

    /**
     * Returns a copy of this settings object with the sustained refill window replaced.
     *
     * @param value New sustained refill window, in seconds.
     * @return A new instance with the updated sustained window.
     */
    @NonNull
    public RateSettings withSustainedWindowSeconds(long value) {
        return new RateSettings(burstCapacity, burstWindowSeconds, sustainedCapacity, value);
    }
}
