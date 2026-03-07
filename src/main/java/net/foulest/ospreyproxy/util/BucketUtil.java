package net.foulest.ospreyproxy.util;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Utility class for managing rate-limiting buckets using Bucket4j and Caffeine.
 *
 * @author Foulest
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class BucketUtil {

    // Rate limit configuration (per-IP)
    private static final int NUMBER_OF_PROVIDERS = 2;
    private static final int IP_BURST_CAPACITY = 15 * NUMBER_OF_PROVIDERS;
    private static final int IP_SUSTAINED_CAPACITY = 600 * NUMBER_OF_PROVIDERS;

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

    /**
     * Gets or creates a rate-limiting burst bucket for the given IP address.
     *
     * @param ip The hashed IP address to get the bucket for.
     * @return A Bucket instance for the given IP address for burst rate limiting.
     */
    @SuppressWarnings("NestedMethodCall")
    public static Bucket getBurstBucket(@NonNull String ip) {
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
     * @param ip The hashed IP address to get the bucket for.
     * @return A Bucket instance for the given IP address for sustained rate limiting.
     */
    @SuppressWarnings("NestedMethodCall")
    public static Bucket getSustainedBucket(@NonNull String ip) {
        return SUSTAINED_BUCKETS.get(ip, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(IP_SUSTAINED_CAPACITY)
                        .refillIntervally(IP_SUSTAINED_CAPACITY, SUSTAINED_DURATION)
                        .build())
                .build());
    }
}
