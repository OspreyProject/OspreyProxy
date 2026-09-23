/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
import io.github.bucket4j.Bucket;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import org.assertj.core.api.Assertions;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.time.Instant;

class AbstractProviderTest {

    private static class TestProvider extends AbstractProvider {

        TestProvider() {
        }

        TestProvider(Duration allowedCacheTTL, Duration blockedCacheTTL) {
            super(allowedCacheTTL, blockedCacheTTL);
        }

        @Override
        public @NonNull String getDisplayName() {
            return "Test";
        }

        @Override
        public @NonNull String getEndpointName() {
            return "test";
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }

    private static class RateLimitDisabledProvider extends TestProvider {

        @Override
        public boolean isRateLimitingEnabled() {
            return false;
        }
    }

    private static class AbuseLimitDisabledProvider extends TestProvider {

        @Override
        public boolean isAbuseLimitingEnabled() {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static <K, V> Cache<K, V> cacheField(AbstractProvider provider, String fieldName) throws ReflectiveOperationException {
        Field field = AbstractProvider.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (Cache<K, V>) field.get(provider);
    }

    private final TestProvider provider = new TestProvider();

    // --- Constructors ---

    @Test
    void defaultConstructorAllowsRoundTripCaching() {
        TestProvider defaultProvider = new TestProvider();
        defaultProvider.putCachedResult("example.com", LookupVerdict.ALLOWED);
        Assertions.assertThat(defaultProvider.getCachedResult("example.com")).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void customConstructorAllowsRoundTripCaching() {
        TestProvider customProvider = new TestProvider(Duration.ofMinutes(30), Duration.ofMinutes(5));
        customProvider.putCachedResult("example.com", LookupVerdict.of(LookupResult.MALICIOUS));
        Assertions.assertThat(customProvider.getCachedResult("example.com"))
                .isEqualTo(LookupVerdict.of(LookupResult.MALICIOUS));
    }

    // --- getCachedResult / putCachedResult ---

    @Test
    void getCachedResultReturnsNullWhenNothingCached() {
        Assertions.assertThat(provider.getCachedResult("uncached.example.com")).isNull();
    }

    @Test
    void putCachedResultDoesNothingForFailedVerdict() {
        provider.putCachedResult("failed.example.com", LookupVerdict.FAILED);
        Assertions.assertThat(provider.getCachedResult("failed.example.com")).isNull();
    }

    @Test
    void putCachedResultDoesNothingForRateLimitedVerdict() {
        provider.putCachedResult("limited.example.com", LookupVerdict.RATE_LIMITED);
        Assertions.assertThat(provider.getCachedResult("limited.example.com")).isNull();
    }

    @Test
    void putCachedResultCachesAllowedOnlyVerdictInAllowedCache() {
        provider.putCachedResult("allowed.example.com", LookupVerdict.ALLOWED);
        Assertions.assertThat(provider.getCachedResult("allowed.example.com")).isEqualTo(LookupVerdict.ALLOWED);
    }

    @Test
    void putCachedResultCachesNonAllowedVerdictInBlockedCache() {
        provider.putCachedResult("malicious.example.com", LookupVerdict.of(LookupResult.MALICIOUS));
        Assertions.assertThat(provider.getCachedResult("malicious.example.com"))
                .isEqualTo(LookupVerdict.of(LookupResult.MALICIOUS));
    }

    // --- isRateLimitingEnabled ---

    @Test
    void isRateLimitingEnabledDefaultsToTrue() {
        Assertions.assertThat(provider.isRateLimitingEnabled()).isTrue();
    }

    // --- Buckets ---

    @Test
    void getBurstBucketReturnsSameInstanceForSameIp() {
        Bucket first = provider.getBurstBucket("1.2.3.4");
        Bucket second = provider.getBurstBucket("1.2.3.4");
        Assertions.assertThat(first).isNotNull().isSameAs(second);
    }

    @Test
    void getSustainedBucketReturnsSameInstanceForSameIp() {
        Bucket first = provider.getSustainedBucket("1.2.3.4");
        Bucket second = provider.getSustainedBucket("1.2.3.4");
        Assertions.assertThat(first).isNotNull().isSameAs(second);
    }

    @Test
    void getInvalidRequestBucketReturnsSameInstanceForSameIp() {
        Bucket first = provider.getInvalidRequestBucket("1.2.3.4");
        Bucket second = provider.getInvalidRequestBucket("1.2.3.4");
        Assertions.assertThat(first).isNotNull().isSameAs(second);
    }

    // --- isBurstBlocked ---

    @Test
    void isBurstBlockedReturnsFalseWhenRateLimitingDisabled() {
        RateLimitDisabledProvider disabled = new RateLimitDisabledProvider();
        disabled.blockBurst("1.2.3.4");
        Assertions.assertThat(disabled.isBurstBlocked("1.2.3.4")).isFalse();
    }

    @Test
    void isBurstBlockedReturnsFalseWhenNoBlockRecorded() {
        Assertions.assertThat(provider.isBurstBlocked("no-block.example")).isFalse();
    }

    @Test
    void isBurstBlockedReturnsTrueWhenBlockedUntilFuture() {
        provider.blockBurst("blocked.example");
        Assertions.assertThat(provider.isBurstBlocked("blocked.example")).isTrue();
    }

    @Test
    void isBurstBlockedReturnsFalseWhenBlockHasExpired() throws ReflectiveOperationException {
        Cache<String, Instant> cache = cacheField(provider, "burstBlockedCache");
        cache.put("expired.example", Instant.now().minusSeconds(10));
        Assertions.assertThat(provider.isBurstBlocked("expired.example")).isFalse();
    }

    // --- isSustainedBlocked ---

    @Test
    void isSustainedBlockedReturnsFalseWhenRateLimitingDisabled() {
        RateLimitDisabledProvider disabled = new RateLimitDisabledProvider();
        disabled.blockSustained("1.2.3.4");
        Assertions.assertThat(disabled.isSustainedBlocked("1.2.3.4")).isFalse();
    }

    @Test
    void isSustainedBlockedReturnsFalseWhenNoBlockRecorded() {
        Assertions.assertThat(provider.isSustainedBlocked("no-block.example")).isFalse();
    }

    @Test
    void isSustainedBlockedReturnsTrueWhenBlockedUntilFuture() {
        provider.blockSustained("blocked.example");
        Assertions.assertThat(provider.isSustainedBlocked("blocked.example")).isTrue();
    }

    @Test
    void isSustainedBlockedReturnsFalseWhenBlockHasExpired() throws ReflectiveOperationException {
        Cache<String, Instant> cache = cacheField(provider, "sustainedBlockedCache");
        cache.put("expired.example", Instant.now().minusSeconds(10));
        Assertions.assertThat(provider.isSustainedBlocked("expired.example")).isFalse();
    }

    // --- isInvalidRequestBlocked ---

    @Test
    void isInvalidRequestBlockedReturnsFalseWhenAbuseLimitingDisabled() {
        AbuseLimitDisabledProvider disabled = new AbuseLimitDisabledProvider();
        disabled.blockInvalidRequest("1.2.3.4");
        Assertions.assertThat(disabled.isInvalidRequestBlocked("1.2.3.4")).isFalse();
    }

    @Test
    void isInvalidRequestBlockedReturnsFalseWhenNoBlockRecorded() {
        Assertions.assertThat(provider.isInvalidRequestBlocked("no-block.example")).isFalse();
    }

    @Test
    void isInvalidRequestBlockedReturnsTrueWhenBlockedUntilFuture() {
        provider.blockInvalidRequest("blocked.example");
        Assertions.assertThat(provider.isInvalidRequestBlocked("blocked.example")).isTrue();
    }

    @Test
    void isInvalidRequestBlockedReturnsFalseWhenBlockHasExpired() throws ReflectiveOperationException {
        Cache<String, Instant> cache = cacheField(provider, "invalidRequestBlockedCache");
        cache.put("expired.example", Instant.now().minusSeconds(10));
        Assertions.assertThat(provider.isInvalidRequestBlocked("expired.example")).isFalse();
    }

    // --- blockBurst ---

    @Test
    void blockBurstDoesNothingWhenRateLimitingDisabled() throws ReflectiveOperationException {
        RateLimitDisabledProvider disabled = new RateLimitDisabledProvider();
        disabled.blockBurst("1.2.3.4");
        Cache<String, Integer> violations = cacheField(disabled, "burstViolationCount");
        Assertions.assertThat(violations.getIfPresent("1.2.3.4")).isNull();
    }

    @Test
    void blockBurstIncrementsViolationCountAndInvalidatesBucket() throws ReflectiveOperationException {
        Bucket original = provider.getBurstBucket("violator.example");
        provider.blockBurst("violator.example");

        Cache<String, Integer> violations = cacheField(provider, "burstViolationCount");
        Assertions.assertThat(violations.getIfPresent("violator.example")).isEqualTo(1);
        Assertions.assertThat(provider.getBurstBucket("violator.example")).isNotSameAs(original);
    }

    @Test
    void blockBurstCapsBlockDurationAtOneHour() throws ReflectiveOperationException {
        for (int i = 0; i < 20; i++) {
            provider.blockBurst("repeat-violator.example");
        }

        Cache<String, Instant> blocked = cacheField(provider, "burstBlockedCache");
        Instant unblockTime = blocked.getIfPresent("repeat-violator.example");
        Assertions.assertThat(unblockTime).isNotNull();

        long secondsUntilUnblock = Duration.between(Instant.now(), unblockTime).getSeconds();
        Assertions.assertThat(secondsUntilUnblock).isBetween(3590L, 3600L);
    }

    // --- blockSustained ---

    @Test
    void blockSustainedDoesNothingWhenRateLimitingDisabled() throws ReflectiveOperationException {
        RateLimitDisabledProvider disabled = new RateLimitDisabledProvider();
        disabled.blockSustained("1.2.3.4");
        Cache<String, Integer> violations = cacheField(disabled, "sustainedViolationCount");
        Assertions.assertThat(violations.getIfPresent("1.2.3.4")).isNull();
    }

    @Test
    void blockSustainedIncrementsViolationCountAndInvalidatesBucket() throws ReflectiveOperationException {
        Bucket original = provider.getSustainedBucket("violator.example");
        provider.blockSustained("violator.example");

        Cache<String, Integer> violations = cacheField(provider, "sustainedViolationCount");
        Assertions.assertThat(violations.getIfPresent("violator.example")).isEqualTo(1);
        Assertions.assertThat(provider.getSustainedBucket("violator.example")).isNotSameAs(original);
    }

    @Test
    void blockSustainedCapsBlockDurationAtOneHour() throws ReflectiveOperationException {
        for (int i = 0; i < 20; i++) {
            provider.blockSustained("repeat-violator.example");
        }

        Cache<String, Instant> blocked = cacheField(provider, "sustainedBlockedCache");
        Instant unblockTime = blocked.getIfPresent("repeat-violator.example");
        Assertions.assertThat(unblockTime).isNotNull();

        long secondsUntilUnblock = Duration.between(Instant.now(), unblockTime).getSeconds();
        Assertions.assertThat(secondsUntilUnblock).isBetween(3590L, 3600L);
    }

    // --- blockInvalidRequest ---

    @Test
    void blockInvalidRequestDoesNothingWhenAbuseLimitingDisabled() throws ReflectiveOperationException {
        AbuseLimitDisabledProvider disabled = new AbuseLimitDisabledProvider();
        disabled.blockInvalidRequest("1.2.3.4");
        Cache<String, Integer> violations = cacheField(disabled, "invalidRequestViolationCount");
        Assertions.assertThat(violations.getIfPresent("1.2.3.4")).isNull();
    }

    @Test
    void blockInvalidRequestIncrementsViolationCountAndInvalidatesBucket() throws ReflectiveOperationException {
        Bucket original = provider.getInvalidRequestBucket("violator.example");
        provider.blockInvalidRequest("violator.example");

        Cache<String, Integer> violations = cacheField(provider, "invalidRequestViolationCount");
        Assertions.assertThat(violations.getIfPresent("violator.example")).isEqualTo(1);
        Assertions.assertThat(provider.getInvalidRequestBucket("violator.example")).isNotSameAs(original);
    }

    @Test
    void blockInvalidRequestCapsBlockDurationAtOneHour() throws ReflectiveOperationException {
        for (int i = 0; i < 20; i++) {
            provider.blockInvalidRequest("repeat-violator.example");
        }

        Cache<String, Instant> blocked = cacheField(provider, "invalidRequestBlockedCache");
        Instant unblockTime = blocked.getIfPresent("repeat-violator.example");
        Assertions.assertThat(unblockTime).isNotNull();

        long secondsUntilUnblock = Duration.between(Instant.now(), unblockTime).getSeconds();
        Assertions.assertThat(secondsUntilUnblock).isBetween(3590L, 3600L);
    }

    // --- getViolatorId ---

    @Test
    void getViolatorIdReturnsSameIdForSameIp() {
        String first = provider.getViolatorId("1.2.3.4");
        String second = provider.getViolatorId("1.2.3.4");
        Assertions.assertThat(first).isEqualTo(second);
    }

    @Test
    void getViolatorIdReturnsDifferentIdsForDifferentIps() {
        String first = provider.getViolatorId("1.2.3.4");
        String second = provider.getViolatorId("5.6.7.8");
        Assertions.assertThat(first).isNotEqualTo(second);
        Assertions.assertThat(first).isEqualTo("#1");
        Assertions.assertThat(second).isEqualTo("#2");
    }
}
