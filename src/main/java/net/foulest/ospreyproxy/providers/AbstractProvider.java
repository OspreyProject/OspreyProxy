/*
 * OspreyProxy - backend code for our proxy server using Spring MVC.
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
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.HashUtil;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Abstract base class for all Provider implementations, providing common caching and rate limiting logic.
 */
public abstract class AbstractProvider implements Provider {

    // Pattern for validating UUIDs
    protected static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    // Caches for storing buckets per IP address
    private final Cache<String, Bucket> burstBucketCache = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();
    private final Cache<String, Bucket> sustainedBucketCache = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();
    private final Cache<String, Bucket> invalidRequestBucketCache = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();

    // Caches for tracking temporarily blocked IPs
    private final Cache<String, Instant> burstBlockedCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();
    private final Cache<String, Instant> sustainedBlockedCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(2))
            .maximumSize(100_000)
            .build();
    private final Cache<String, Instant> invalidRequestBlockedCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(2))
            .maximumSize(100_000)
            .build();

    // Caches for counting violations to implement exponential backoff blocking
    private final Cache<String, Integer> burstViolationCount = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();
    private final Cache<String, Integer> sustainedViolationCount = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();
    private final Cache<String, Integer> invalidRequestViolationCount = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();

    // Assigns a stable, session-scoped numeric ID to each violating IP for log correlation
    // without logging the hashed IP itself. Resets on restart.
    private final AtomicInteger violatorCounter = new AtomicInteger(0);
    private final Cache<String, String> violatorIdCache = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(24))
            .maximumSize(100_000)
            .build();

    // Separate caches per TTL tier; Caffeine does not support per-entry TTLs.
    private final Cache<String, LookupResult> allowedCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(1))
            .maximumSize(50_000)
            .build();
    private final Cache<String, LookupResult> blockedCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(15))
            .maximumSize(10_000)
            .build();

    // Per-instance Bandwidth definitions, built once from this provider's config methods
    private final Bandwidth burstBandwidth;
    private final Bandwidth sustainedBandwidth;
    private final Bandwidth invalidRequestBandwidth;

    // Per-instance block durations, captured from config methods at construction time
    private final Duration burstBlockDuration;
    private final Duration sustainedBlockDuration;
    private final Duration invalidRequestBlockDuration;

    protected AbstractProvider() {
        int burstCapacity = rateLimitBurstCapacity();
        Duration burstWindow = rateLimitBurstWindow();

        burstBandwidth = Bandwidth.builder()
                .capacity(burstCapacity)
                .refillGreedy(burstCapacity, burstWindow)
                .build();

        int sustainedCapacity = rateLimitSustainedCapacity();
        Duration sustainedWindow = rateLimitSustainedWindow();

        sustainedBandwidth = Bandwidth.builder()
                .capacity(sustainedCapacity)
                .refillGreedy(sustainedCapacity, sustainedWindow)
                .build();

        int invalidRequestCapacity = rateLimitInvalidRequestCapacity();
        Duration invalidRequestWindow = rateLimitInvalidRequestWindow();

        invalidRequestBandwidth = Bandwidth.builder()
                .capacity(invalidRequestCapacity)
                .refillGreedy(invalidRequestCapacity, invalidRequestWindow)
                .build();

        burstBlockDuration = rateLimitBurstBlockDuration();
        sustainedBlockDuration = rateLimitSustainedBlockDuration();
        invalidRequestBlockDuration = rateLimitInvalidRequestBlockDuration();
    }

    /**
     * Returns a cached result for the given lookup string if one exists, otherwise
     * performs the lookup and caches the result.
     *
     * @param lookupStr The validated string to look up (host or URL).
     * @return The {@link LookupResult} for this lookup, from cache or live.
     * @throws UnsupportedOperationException if the provider does not support self-contained lookup.
     */
    @SuppressWarnings("NestedMethodCall")
    @Override
    public @NonNull LookupResult cachedLookup(@NonNull String lookupStr) {
        throw new UnsupportedOperationException(
                getClass().getSimpleName() + " does not support cachedLookup(); "
                        + "use getCachedResult/putCachedResult via ProxyHandler instead."
        );
    }

    /**
     * Gets a cached result for the given lookup string if one exists, or {@code null} if not.
     *
     * @param lookupStr The validated string to look up (host or URL).
     * @return The cached {@link LookupResult} for this string, or {@code null} if no cache entry exists.
     */
    public final @Nullable LookupResult getCachedResult(@NonNull String lookupStr) {
        String key = HashUtil.hashUrl(lookupStr);
        LookupResult allowed = allowedCache.getIfPresent(key);
        return allowed != null ? allowed : blockedCache.getIfPresent(key);
    }

    /**
     * Caches the given result for the given lookup string. Does nothing if the result is {@link LookupResult#FAILED}.
     *
     * @param lookupStr The validated string that was looked up (host or URL).
     * @param result The {@link LookupResult} to cache for this string, if not {@link LookupResult#FAILED}.
     */
    public final void putCachedResult(@NonNull String lookupStr, @NonNull LookupResult result) {
        if (result == LookupResult.FAILED) {
            return;
        }

        String key = HashUtil.hashUrl(lookupStr);

        if (result == LookupResult.ALLOWED) {
            allowedCache.put(key, LookupResult.ALLOWED);
        } else {
            blockedCache.put(key, result);
        }
    }

    /**
     * Whether rate limiting is enabled for this provider.
     * Override to return {@code false} to disable all rate limiting.
     */
    @Override
    public boolean isRateLimitingEnabled() {
        return true;
    }

    /**
     * Maximum burst request capacity per IP within {@link #rateLimitBurstWindow()}.
     */
    private static int rateLimitBurstCapacity() {
        return 11;
    }

    /**
     * Maximum sustained request capacity per IP within {@link #rateLimitSustainedWindow()}.
     */
    private static int rateLimitSustainedCapacity() {
        return 400;
    }

    /**
     * Maximum invalid request capacity per IP within {@link #rateLimitInvalidRequestWindow()}.
     */
    private static int rateLimitInvalidRequestCapacity() {
        return 5;
    }

    /**
     * Rolling window for burst rate limiting.
     */
    @NonNull
    private static Duration rateLimitBurstWindow() {
        return Duration.ofSeconds(1);
    }

    /**
     * Rolling window for sustained rate limiting.
     */
    @NonNull
    private static Duration rateLimitSustainedWindow() {
        return Duration.ofMinutes(1);
    }

    /**
     * Rolling window for invalid request rate limiting.
     */
    @NonNull
    private static Duration rateLimitInvalidRequestWindow() {
        return Duration.ofMinutes(1);
    }

    /**
     * How long to block an IP on the first burst violation (doubles on each repeat).
     */
    @NonNull
    private static Duration rateLimitBurstBlockDuration() {
        return Duration.ofSeconds(5);
    }

    /**
     * How long to block an IP on the first sustained violation (doubles on each repeat).
     */
    @NonNull
    private static Duration rateLimitSustainedBlockDuration() {
        return Duration.ofMinutes(1);
    }

    /**
     * How long to block an IP on the first invalid-request violation (doubles on each repeat).
     */
    @NonNull
    private static Duration rateLimitInvalidRequestBlockDuration() {
        return Duration.ofSeconds(5);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Bucket getBurstBucket(@NonNull String ip) {
        return burstBucketCache.get(ip, k -> Bucket.builder().addLimit(burstBandwidth).build());
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Bucket getSustainedBucket(@NonNull String ip) {
        return sustainedBucketCache.get(ip, k -> Bucket.builder().addLimit(sustainedBandwidth).build());
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull Bucket getInvalidRequestBucket(@NonNull String ip) {
        return invalidRequestBucketCache.get(ip, k -> Bucket.builder().addLimit(invalidRequestBandwidth).build());
    }

    @Override
    public boolean isBurstBlocked(@NonNull String ip) {
        if (!isRateLimitingEnabled()) {
            return false;
        }

        Instant unblockTime = burstBlockedCache.getIfPresent(ip);
        return unblockTime != null && Instant.now().isBefore(unblockTime);
    }

    @Override
    public boolean isSustainedBlocked(@NonNull String ip) {
        if (!isRateLimitingEnabled()) {
            return false;
        }

        Instant unblockTime = sustainedBlockedCache.getIfPresent(ip);
        return unblockTime != null && Instant.now().isBefore(unblockTime);
    }

    @Override
    public boolean isInvalidRequestBlocked(@NonNull String ip) {
        if (!isRateLimitingEnabled()) {
            return false;
        }

        Instant unblockTime = invalidRequestBlockedCache.getIfPresent(ip);
        return unblockTime != null && Instant.now().isBefore(unblockTime);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public void blockBurst(@NonNull String ip) {
        if (!isRateLimitingEnabled()) {
            return;
        }

        int violations = burstViolationCount.asMap().merge(ip, 1, Integer::sum);
        long blockSeconds = Math.min(burstBlockDuration.getSeconds() * (1L << Math.min(violations - 1, 62)), 3600L);

        burstBlockedCache.put(ip, Instant.now().plusSeconds(blockSeconds));
        burstBucketCache.invalidate(ip);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public void blockSustained(@NonNull String ip) {
        if (!isRateLimitingEnabled()) {
            return;
        }

        int violations = sustainedViolationCount.asMap().merge(ip, 1, Integer::sum);
        long blockSeconds = Math.min(sustainedBlockDuration.getSeconds() * (1L << Math.min(violations - 1, 62)), 3600L);

        sustainedBlockedCache.put(ip, Instant.now().plusSeconds(blockSeconds));
        sustainedBucketCache.invalidate(ip);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public void blockInvalidRequest(@NonNull String ip) {
        if (!isRateLimitingEnabled()) {
            return;
        }

        int violations = invalidRequestViolationCount.asMap().merge(ip, 1, Integer::sum);
        long blockSeconds = Math.min(invalidRequestBlockDuration.getSeconds() * (1L << Math.min(violations - 1, 62)), 3600L);

        invalidRequestBlockedCache.put(ip, Instant.now().plusSeconds(blockSeconds));
        invalidRequestBucketCache.invalidate(ip);
    }

    @Override
    @SuppressWarnings("NestedMethodCall")
    public @NonNull String getViolatorId(@NonNull String ip) {
        return violatorIdCache.get(ip, k -> "#" + violatorCounter.incrementAndGet());
    }
}
