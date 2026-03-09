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

import java.time.Duration;
import java.util.Map;

/**
 * Provider implementation for AlphaMountain.
 */
@Component
public class AlphaMountainProvider implements Provider {

    // API Key and URL configuration
    private static final String API_KEY = System.getenv("ALPHAMOUNTAIN_API_KEY");
    private static final String API_URL = "https://api.alphamountain.ai/category/uri";
    private static final String UUID_PATTERN = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    // Rate limiting configuration
    private static final int BURST_CAPACITY = 11;
    private static final int SUSTAINED_CAPACITY = 400;
    private static final Duration BURST_DURATION = Duration.ofSeconds(1);
    private static final Duration SUSTAINED_DURATION = Duration.ofMinutes(1);
    private static final Duration BURST_BLOCK_DURATION = Duration.ofSeconds(5);
    private static final Duration SUSTAINED_BLOCK_DURATION = Duration.ofMinutes(1);

    // Bandwidth definitions for Bucket4j
    private static final Bandwidth BURST_BANDWIDTH = Bandwidth.builder()
            .capacity(BURST_CAPACITY)
            .refillIntervally(BURST_CAPACITY, BURST_DURATION)
            .build();
    private static final Bandwidth SUSTAINED_BANDWIDTH = Bandwidth.builder()
            .capacity(SUSTAINED_CAPACITY)
            .refillIntervally(SUSTAINED_CAPACITY, SUSTAINED_DURATION)
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

    // Caches for tracking temporarily blocked IPs; entries expire after their block duration
    private static final Cache<String, Boolean> BURST_BLOCKED_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(BURST_BLOCK_DURATION)
            .maximumSize(100_000)
            .build();
    private static final Cache<String, Boolean> SUSTAINED_BLOCKED_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(SUSTAINED_BLOCK_DURATION)
            .maximumSize(100_000)
            .build();

    // Static request body parameters
    private static final String LICENSE = API_KEY;
    private static final int VERSION = 1;
    private static final String TYPE = "partner.info";

    @PostConstruct
    public void validateConfig() {
        // Check if the key is blank or doesn't match UUID spec
        if (!StressTestUtil.isEnabled() && (API_KEY == null || API_KEY.isBlank() || !API_KEY.matches(UUID_PATTERN))) {
            throw new IllegalStateException("ALPHAMOUNTAIN_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getName() {
        return "alphaMountain";
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NonNull Map<String, Object> buildBody(@NonNull String url) {
        return Map.of(
                "uri", url,
                "license", LICENSE,
                "version", VERSION,
                "type", TYPE
        );
    }

    @Override
    public int getBurstCapacity() {
        return BURST_CAPACITY;
    }

    @Override
    public int getSustainedCapacity() {
        return SUSTAINED_CAPACITY;
    }

    @Override
    public @NonNull Duration getBurstDuration() {
        return BURST_DURATION;
    }

    @Override
    public @NonNull Duration getSustainedDuration() {
        return SUSTAINED_DURATION;
    }

    @Override
    public @NonNull Bandwidth getBurstBandwidth() {
        return BURST_BANDWIDTH;
    }

    @Override
    public @NonNull Bandwidth getSustainedBandwidth() {
        return SUSTAINED_BANDWIDTH;
    }

    @Override
    public @NonNull Cache<String, Bucket> getBurstBucketCache() {
        return BURST_BUCKET_CACHE;
    }

    @Override
    public @NonNull Cache<String, Bucket> getSustainedBucketCache() {
        return SUSTAINED_BUCKET_CACHE;
    }

    @Override
    public @NonNull Bucket getBurstBucket(@NonNull String ip) {
        return BURST_BUCKET_CACHE.get(ip, k -> Bucket.builder().addLimit(BURST_BANDWIDTH).build());
    }

    @Override
    public @NonNull Bucket getSustainedBucket(@NonNull String ip) {
        return SUSTAINED_BUCKET_CACHE.get(ip, k -> Bucket.builder().addLimit(SUSTAINED_BANDWIDTH).build());
    }

    @Override
    public @NonNull Duration getBurstBlockDuration() {
        return BURST_BLOCK_DURATION;
    }

    @Override
    public @NonNull Duration getSustainedBlockDuration() {
        return SUSTAINED_BLOCK_DURATION;
    }

    @Override
    public @NonNull Cache<String, Boolean> getBurstBlockedCache() {
        return BURST_BLOCKED_CACHE;
    }

    @Override
    public @NonNull Cache<String, Boolean> getSustainedBlockedCache() {
        return SUSTAINED_BLOCKED_CACHE;
    }

    @Override
    public boolean isBurstBlocked(@NonNull String ip) {
        return BURST_BLOCKED_CACHE.getIfPresent(ip) != null;
    }

    @Override
    public boolean isSustainedBlocked(@NonNull String ip) {
        return SUSTAINED_BLOCKED_CACHE.getIfPresent(ip) != null;
    }

    @Override
    public void blockBurst(@NonNull String ip) {
        BURST_BLOCKED_CACHE.put(ip, Boolean.TRUE);
    }

    @Override
    public void blockSustained(@NonNull String ip) {
        SUSTAINED_BLOCKED_CACHE.put(ip, Boolean.TRUE);
    }
}
