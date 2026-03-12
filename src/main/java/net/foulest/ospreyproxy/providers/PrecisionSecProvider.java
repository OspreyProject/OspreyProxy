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
package net.foulest.ospreyproxy.providers;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.annotation.PostConstruct;
import net.foulest.ospreyproxy.util.StressTestUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Provider implementation for PrecisionSec.
 */
@Component
public class PrecisionSecProvider implements Provider {

    // API Key and URL configuration
    private static final String API_KEY = System.getenv("PRECISIONSEC_API_KEY");
    private static final String API_URL = "https://api.precisionsec.com/check_domain/";
    private static final String UUID_PATTERN = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    // Rate limiting capacity
    private static final int BURST_CAPACITY = 11;
    private static final int SUSTAINED_CAPACITY = 400;
    private static final int INVALID_REQUEST_CAPACITY = 5;

    // Rate limiting windows
    private static final Duration BURST_WINDOW = Duration.ofSeconds(1);
    private static final Duration SUSTAINED_WINDOW = Duration.ofMinutes(1);
    private static final Duration INVALID_REQUEST_WINDOW = Duration.ofMinutes(1);

    // Rate limiting block durations
    private static final Duration BURST_BLOCK_DURATION = Duration.ofSeconds(5);
    private static final Duration SUSTAINED_BLOCK_DURATION = Duration.ofMinutes(1);
    private static final Duration INVALID_REQUEST_BLOCK_DURATION = Duration.ofMinutes(5);

    // Bandwidth definitions for Bucket4j
    private static final Bandwidth BURST_BANDWIDTH = Bandwidth.builder()
            .capacity(BURST_CAPACITY)
            .refillGreedy(BURST_CAPACITY, BURST_WINDOW)
            .build();
    private static final Bandwidth SUSTAINED_BANDWIDTH = Bandwidth.builder()
            .capacity(SUSTAINED_CAPACITY)
            .refillGreedy(SUSTAINED_CAPACITY, SUSTAINED_WINDOW)
            .build();
    private static final Bandwidth INVALID_REQUEST_BANDWIDTH = Bandwidth.builder()
            .capacity(INVALID_REQUEST_CAPACITY)
            .refillGreedy(INVALID_REQUEST_CAPACITY, INVALID_REQUEST_WINDOW)
            .build();

    // Caches for storing buckets per IP address
    private static final Cache<String, Bucket> BURST_BUCKET_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Bucket> SUSTAINED_BUCKET_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Bucket> INVALID_REQUEST_BUCKET_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();

    // Caches for tracking temporarily blocked IPs; entries expire after their block duration
    private static final Cache<String, Instant> BURST_BLOCKED_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Instant> SUSTAINED_BLOCKED_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(2))
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Instant> INVALID_REQUEST_BLOCKED_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(2))
            .maximumSize(100_000)
            .build();

    // Caches for counting violations to implement exponential backoff blocking
    private static final Cache<String, Integer> BURST_VIOLATION_COUNT = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Integer> SUSTAINED_VIOLATION_COUNT = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Integer> INVALID_REQUEST_VIOLATION_COUNT = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();

    // Assigns a stable, session-scoped numeric ID to each violating IP for log correlation
    // without logging the hashed IP itself. Resets on restart.
    private static final AtomicInteger VIOLATOR_COUNTER = new AtomicInteger(0);
    private static final Cache<String, String> VIOLATOR_ID_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();

    @PostConstruct
    public void validateConfig() {
        // Check if the key is blank or doesn't match UUID spec
        if (!StressTestUtil.isEnabled() && (API_KEY == null || API_KEY.isBlank() || !API_KEY.matches(UUID_PATTERN))) {
            throw new IllegalStateException("PRECISIONSEC_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getName() {
        return "PrecisionSec";
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NonNull String getMethod() {
        return "GET";
    }

    @Override
    public @NonNull Map<String, String> getHeaders() {
        return Map.of("API-Key", API_KEY);
    }

    @Override
    public @NonNull String buildRequestUrl(@NonNull String url) {
        String encoded = URLEncoder.encode(url, StandardCharsets.UTF_8);
        return API_URL + encoded;
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Bucket getBurstBucket(@NonNull String ip) {
        return BURST_BUCKET_CACHE.get(ip, k -> Bucket.builder().addLimit(BURST_BANDWIDTH).build());
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Bucket getSustainedBucket(@NonNull String ip) {
        return SUSTAINED_BUCKET_CACHE.get(ip, k -> Bucket.builder().addLimit(SUSTAINED_BANDWIDTH).build());
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Bucket getInvalidRequestBucket(@NonNull String ip) {
        return INVALID_REQUEST_BUCKET_CACHE.get(ip, k -> Bucket.builder().addLimit(INVALID_REQUEST_BANDWIDTH).build());
    }

    @Override
    public boolean isBurstBlocked(@NonNull String ip) {
        Instant unblockTime = BURST_BLOCKED_CACHE.getIfPresent(ip);
        return unblockTime != null && Instant.now().isBefore(unblockTime);
    }

    @Override
    public boolean isSustainedBlocked(@NonNull String ip) {
        Instant unblockTime = SUSTAINED_BLOCKED_CACHE.getIfPresent(ip);
        return unblockTime != null && Instant.now().isBefore(unblockTime);
    }

    @Override
    public boolean isInvalidRequestBlocked(@NonNull String ip) {
        Instant unblockTime = INVALID_REQUEST_BLOCKED_CACHE.getIfPresent(ip);
        return unblockTime != null && Instant.now().isBefore(unblockTime);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public void blockBurst(@NonNull String ip) {
        int violations = BURST_VIOLATION_COUNT.get(ip, k -> 0) + 1;
        BURST_VIOLATION_COUNT.put(ip, violations);

        long blockSeconds = Math.min(BURST_BLOCK_DURATION.getSeconds() * (1L << (violations - 1)), 3600L);
        BURST_BLOCKED_CACHE.put(ip, Instant.now().plusSeconds(blockSeconds));
        BURST_BUCKET_CACHE.invalidate(ip);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public void blockSustained(@NonNull String ip) {
        int violations = SUSTAINED_VIOLATION_COUNT.get(ip, k -> 0) + 1;
        SUSTAINED_VIOLATION_COUNT.put(ip, violations);

        long blockSeconds = Math.min(SUSTAINED_BLOCK_DURATION.getSeconds() * (1L << (violations - 1)), 3600L);
        SUSTAINED_BLOCKED_CACHE.put(ip, Instant.now().plusSeconds(blockSeconds));
        SUSTAINED_BUCKET_CACHE.invalidate(ip);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public void blockInvalidRequest(@NonNull String ip) {
        int violations = INVALID_REQUEST_VIOLATION_COUNT.get(ip, k -> 0) + 1;
        INVALID_REQUEST_VIOLATION_COUNT.put(ip, violations);

        long blockSeconds = Math.min(INVALID_REQUEST_BLOCK_DURATION.getSeconds() * (1L << (violations - 1)), 3600L);
        INVALID_REQUEST_BLOCKED_CACHE.put(ip, Instant.now().plusSeconds(blockSeconds));
        INVALID_REQUEST_BUCKET_CACHE.invalidate(ip);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull String getViolatorId(@NonNull String ip) {
        return VIOLATOR_ID_CACHE.get(ip, k -> "#" + VIOLATOR_COUNTER.incrementAndGet());
    }
}
