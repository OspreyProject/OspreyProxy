/*
 * OspreyProxy - backend code for our proxy server using Spring WebFlux.
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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.local.LocalBucketBuilder;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;

import java.time.Duration;

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

    // Pre-built burst Bandwidth object
    private static final Bandwidth BURST_BANDWIDTH = Bandwidth.builder()
            .capacity(IP_BURST_CAPACITY)
            .refillIntervally(IP_BURST_CAPACITY, BURST_DURATION)
            .build();

    // Pre-built sustained Bandwidth object
    private static final Bandwidth SUSTAINED_BANDWIDTH = Bandwidth.builder()
            .capacity(IP_SUSTAINED_CAPACITY)
            .refillIntervally(IP_SUSTAINED_CAPACITY, SUSTAINED_DURATION)
            .build();

    // Cache for per-IP rate-limiting burst buckets
    private static final Cache<String, Bucket> BURST_BUCKETS = Caffeine.newBuilder()
            .maximumSize(100_000)
            .build();

    // Cache for per-IP rate-limiting sustained buckets
    private static final Cache<String, Bucket> SUSTAINED_BUCKETS = Caffeine.newBuilder()
            .maximumSize(100_000)
            .build();

    /**
     * Gets or creates a rate-limiting burst bucket for the given IP address.
     *
     * @param ip The hashed IP address to get the bucket for.
     * @return A Bucket instance for the given IP address for burst rate limiting.
     */
    public static Bucket getBurstBucket(@NonNull String ip) {
        Bucket bucket = BURST_BUCKETS.getIfPresent(ip);

        if (bucket != null) {
            return bucket;
        }

        return BURST_BUCKETS.get(ip, k -> {
            LocalBucketBuilder builder = Bucket.builder().addLimit(BURST_BANDWIDTH);
            return builder.build();
        });
    }

    /**
     * Gets or creates a rate-limiting sustained bucket for the given IP address.
     *
     * @param ip The hashed IP address to get the bucket for.
     * @return A Bucket instance for the given IP address for sustained rate limiting.
     */
    public static Bucket getSustainedBucket(@NonNull String ip) {
        Bucket bucket = SUSTAINED_BUCKETS.getIfPresent(ip);

        if (bucket != null) {
            return bucket;
        }

        return SUSTAINED_BUCKETS.get(ip, k -> {
            LocalBucketBuilder builder = Bucket.builder().addLimit(SUSTAINED_BANDWIDTH);
            return builder.build();
        });
    }
}
