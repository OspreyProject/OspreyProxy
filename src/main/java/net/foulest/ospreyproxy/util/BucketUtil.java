package net.foulest.ospreyproxy.util;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jetbrains.annotations.NotNull;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Utility class for managing rate-limiting buckets using Bucket4j and Caffeine.
 *
 * @author Foulest
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class BucketUtil {

    // Update WEEKLY_USERS as the extension grows (~25-30% growth increments)
    private static final int WEEKLY_USERS = 6_000;
    private static final int PEAK_CONCURRENT_USERS = (int) (WEEKLY_USERS / 7.0 * 0.12 * 1.5);

    // Rate limit configuration (per-IP)
    private static final int IP_BURST_CAPACITY = 15;
    private static final int IP_SUSTAINED_CAPACITY = 600;

    // Rate limit configuration (global)
    // Derived from peak concurrency; scales automatically with WEEKLY_USERS
    private static final int GLOBAL_BURST_CAPACITY = PEAK_CONCURRENT_USERS * IP_BURST_CAPACITY;
    private static final int GLOBAL_SUSTAINED_CAPACITY = PEAK_CONCURRENT_USERS * IP_SUSTAINED_CAPACITY;

    // Refill durations for burst and sustained buckets
    private static final Duration BURST_DURATION = Duration.ofSeconds(1);
    private static final Duration SUSTAINED_DURATION = Duration.ofMinutes(1);

    // Cache for per-IP rate-limiting burst buckets
    private static final Cache<String, Bucket> BURST_BUCKETS = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .maximumSize(100_000)
            .build();

    // Cache for per-IP rate-limiting sustained buckets
    private static final Cache<String, Bucket> SUSTAINED_BUCKETS = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS)
            .maximumSize(100_000)
            .build();

    // Global rate-limiting burst bucket
    public static final Bucket GLOBAL_BURST_BUCKET = Bucket.builder()
            .addLimit(Bandwidth.builder()
                    .capacity(GLOBAL_BURST_CAPACITY)
                    .refillIntervally(GLOBAL_BURST_CAPACITY, BURST_DURATION)
                    .build())
            .build();

    // Global rate-limiting sustained bucket
    public static final Bucket GLOBAL_SUSTAINED_BUCKET = Bucket.builder()
            .addLimit(Bandwidth.builder()
                    .capacity(GLOBAL_SUSTAINED_CAPACITY)
                    .refillIntervally(GLOBAL_SUSTAINED_CAPACITY, SUSTAINED_DURATION)
                    .build())
            .build();

    /**
     * Gets or creates a rate-limiting burst bucket for the given IP address.
     *
     * @param ip - The hashed IP address to get the bucket for.
     * @return A Bucket instance for the given IP address for burst rate limiting.
     */
    @SuppressWarnings("NestedMethodCall")
    public static Bucket getBurstBucket(@NotNull String ip) {
        return BURST_BUCKETS.get(ip, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(IP_BURST_CAPACITY)
                        .refillIntervally(IP_BURST_CAPACITY, BURST_DURATION)
                        .build())
                .build());
    }

    /**
     * Gets or creates a rate-limiting sustained bucket for the given IP address.
     *
     * @param ip - The hashed IP address to get the bucket for.
     * @return A Bucket instance for the given IP address for sustained rate limiting.
     */
    @SuppressWarnings("NestedMethodCall")
    public static Bucket getSustainedBucket(@NotNull String ip) {
        return SUSTAINED_BUCKETS.get(ip, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(IP_SUSTAINED_CAPACITY)
                        .refillIntervally(IP_SUSTAINED_CAPACITY, SUSTAINED_DURATION)
                        .build())
                .build());
    }
}
