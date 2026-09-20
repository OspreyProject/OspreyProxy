/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util;

import io.github.bucket4j.Bucket;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.Provider;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

class RateLimitUtilTest {

    private static final String IP = "hashed-ip";
    private static final String NAME = "Provider";

    @Test
    void burstLimiterCoversDisabledBlockedExhaustedAndAllowedStates() {
        Provider provider = Mockito.mock(Provider.class);
        Bucket bucket = Mockito.mock(Bucket.class);
        Mockito.when(provider.getBurstBucket(IP)).thenReturn(bucket);

        Mockito.when(provider.isRateLimitingEnabled()).thenReturn(false);
        Assertions.assertThat(RateLimitUtil.isBurstBlocked(provider, IP, NAME)).isFalse();

        Mockito.when(provider.isRateLimitingEnabled()).thenReturn(true);
        Mockito.when(provider.isBurstBlocked(IP)).thenReturn(true);
        Assertions.assertThat(RateLimitUtil.isBurstBlocked(provider, IP, NAME)).isTrue();

        Mockito.when(provider.isBurstBlocked(IP)).thenReturn(false);
        Mockito.when(bucket.tryConsume(1)).thenReturn(false);
        Mockito.when(provider.getViolatorId(IP)).thenReturn("#1");
        Assertions.assertThat(RateLimitUtil.isBurstBlocked(provider, IP, NAME)).isTrue();
        Mockito.verify(provider).blockBurst(IP);

        Mockito.when(bucket.tryConsume(1)).thenReturn(true);
        Assertions.assertThat(RateLimitUtil.isBurstBlocked(provider, IP, NAME)).isFalse();
    }

    @Test
    void sustainedLimiterCoversDisabledBlockedExhaustedAndAllowedStates() {
        Provider provider = Mockito.mock(Provider.class);
        Bucket bucket = Mockito.mock(Bucket.class);
        Mockito.when(provider.getSustainedBucket(IP)).thenReturn(bucket);

        Mockito.when(provider.isRateLimitingEnabled()).thenReturn(false);
        Assertions.assertThat(RateLimitUtil.isSustainedBlocked(provider, IP, NAME)).isFalse();

        Mockito.when(provider.isRateLimitingEnabled()).thenReturn(true);
        Mockito.when(provider.isSustainedBlocked(IP)).thenReturn(true);
        Mockito.when(provider.getViolatorId(IP)).thenReturn("#2");
        Assertions.assertThat(RateLimitUtil.isSustainedBlocked(provider, IP, NAME)).isTrue();

        Mockito.when(provider.isSustainedBlocked(IP)).thenReturn(false);
        Mockito.when(bucket.tryConsume(1)).thenReturn(false);
        Assertions.assertThat(RateLimitUtil.isSustainedBlocked(provider, IP, NAME)).isTrue();
        Mockito.verify(provider).blockSustained(IP);

        Mockito.when(bucket.tryConsume(1)).thenReturn(true);
        Assertions.assertThat(RateLimitUtil.isSustainedBlocked(provider, IP, NAME)).isFalse();
    }

    @Test
    void invalidRequestRejectionCoversDisabledLimiterAndOptionalMessages() {
        Provider provider = Mockito.mock(Provider.class);
        Mockito.when(provider.isAbuseLimitingEnabled()).thenReturn(false);

        Assertions.assertThatCode(() -> RateLimitUtil.rejectInvalidRequest(provider, IP, NAME, "reason"))
                .doesNotThrowAnyException();
        Assertions.assertThatCode(() -> RateLimitUtil.rejectInvalidRequest(provider, IP, NAME, ""))
                .doesNotThrowAnyException();
        Mockito.verify(provider, Mockito.never()).getInvalidRequestBucket(ArgumentMatchers.anyString());
    }

    @Test
    void invalidRequestRejectionCoversExistingBlockAndBucketExhaustion() {
        Provider provider = Mockito.mock(Provider.class);
        Bucket bucket = Mockito.mock(Bucket.class);
        Mockito.when(provider.isAbuseLimitingEnabled()).thenReturn(true);
        Mockito.when(provider.getViolatorId(IP)).thenReturn("#3");

        Mockito.when(provider.isInvalidRequestBlocked(IP)).thenReturn(true);
        assertTooManyRequests(() -> RateLimitUtil.rejectInvalidRequest(provider, IP, NAME, "reason"));

        Mockito.when(provider.isInvalidRequestBlocked(IP)).thenReturn(false);
        Mockito.when(provider.getInvalidRequestBucket(IP)).thenReturn(bucket);
        Mockito.when(bucket.tryConsume(1)).thenReturn(false);
        assertTooManyRequests(() -> RateLimitUtil.rejectInvalidRequest(provider, IP, NAME, "reason"));
        Mockito.verify(provider).blockInvalidRequest(IP);
    }

    @Test
    void invalidRequestRejectionAllowsTokenWithAndWithoutMessage() {
        Provider provider = Mockito.mock(Provider.class);
        Bucket bucket = Mockito.mock(Bucket.class);
        Mockito.when(provider.isAbuseLimitingEnabled()).thenReturn(true);
        Mockito.when(provider.isInvalidRequestBlocked(IP)).thenReturn(false);
        Mockito.when(provider.getInvalidRequestBucket(IP)).thenReturn(bucket);
        Mockito.when(bucket.tryConsume(1)).thenReturn(true);

        Assertions.assertThatCode(() -> RateLimitUtil.rejectInvalidRequest(provider, IP, NAME, "reason"))
                .doesNotThrowAnyException();
        Assertions.assertThatCode(() -> RateLimitUtil.rejectInvalidRequest(provider, IP, NAME, ""))
                .doesNotThrowAnyException();
    }

    private static void assertTooManyRequests(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        Assertions.assertThatThrownBy(action)
                .isInstanceOf(StatusCodeException.class)
                .hasMessage("429");
    }
}
