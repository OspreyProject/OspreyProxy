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

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import org.apache.hc.core5.http.Method;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Tests the default methods of the {@link Provider} interface via a minimal, direct implementation
 * that does not go through {@link AbstractProvider}.
 */
class ProviderTest {

    /**
     * Minimal stub implementing only the members {@link Provider} declares without a default,
     * so every default method under test resolves to the interface's own implementation.
     */
    private static class MinimalProvider implements Provider {

        private final Bucket bucket = Bucket.builder()
                .addLimit(Bandwidth.simple(1, Duration.ofMinutes(1)))
                .build();

        @Override
        public String getDisplayName() {
            return "Minimal";
        }

        @Override
        public String getEndpointName() {
            return "minimal";
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public Bucket getBurstBucket(String ip) {
            return bucket;
        }

        @Override
        public Bucket getSustainedBucket(String ip) {
            return bucket;
        }

        @Override
        public Bucket getInvalidRequestBucket(String ip) {
            return bucket;
        }

        @Override
        public boolean isBurstBlocked(String ip) {
            return false;
        }

        @Override
        public boolean isSustainedBlocked(String ip) {
            return false;
        }

        @Override
        public boolean isInvalidRequestBlocked(String ip) {
            return false;
        }

        @Override
        public void blockBurst(String ip) {
            // no-op
        }

        @Override
        public void blockSustained(String ip) {
            // no-op
        }

        @Override
        public void blockInvalidRequest(String ip) {
            // no-op
        }

        @Override
        public String getViolatorId(String ip) {
            return "#0";
        }
    }

    /**
     * Stub that overrides {@link Provider#interpret} to return a non-default result, used to verify
     * that {@link Provider#interpretAll} correctly wraps whatever {@code interpret} returns.
     */
    private static class MaliciousInterpretProvider extends MinimalProvider {

        @Override
        public LookupResult interpret(byte[] responseBytes, String url) {
            return LookupResult.MALICIOUS;
        }
    }

    private final Provider provider = new MinimalProvider();

    @Test
    void getApiUrlDefaultsToEmptyString() {
        Assertions.assertThat(provider.getApiUrl()).isEmpty();
    }

    @Test
    void getApiKeyDefaultsToEmptyString() {
        Assertions.assertThat(provider.getApiKey()).isEmpty();
    }

    @Test
    void getMethodDefaultsToGet() {
        Assertions.assertThat(provider.getMethod()).isEqualTo(Method.GET);
    }

    @Test
    void getHeadersDefaultsToEmptyMap() {
        Assertions.assertThat(provider.getHeaders()).isEmpty();
    }

    @Test
    void buildBodyDefaultsToNull() {
        Assertions.assertThat(provider.buildBody("https://example.com")).isNull();
    }

    @Test
    void buildRequestUrlDefaultsToApiUrl() {
        Assertions.assertThat(provider.buildRequestUrl("https://example.com")).isEqualTo(provider.getApiUrl());
    }

    @Test
    void isStripToHostDefaultsToFalse() {
        Assertions.assertThat(provider.isStripToHost()).isFalse();
    }

    @Test
    void isStripToBareHostDefaultsToFalse() {
        Assertions.assertThat(provider.isStripToBareHost()).isFalse();
    }

    @Test
    void isUsingOldHTTPDefaultsToFalse() {
        Assertions.assertThat(provider.isUsingOldHTTP()).isFalse();
    }

    @Test
    void isNotFoundValidResponseDefaultsToFalse() {
        Assertions.assertThat(provider.isNotFoundValidResponse()).isFalse();
    }

    @Test
    void interpretDefaultsToFailed() {
        LookupResult result = provider.interpret("body".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(result).isEqualTo(LookupResult.FAILED);
    }

    @Test
    void interpretAllDefaultsToWrappedFailed() {
        LookupVerdict verdict = provider.interpretAll("body".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void interpretAllWrapsWhateverInterpretReturns() {
        Provider maliciousProvider = new MaliciousInterpretProvider();
        LookupVerdict verdict = maliciousProvider.interpretAll("body".getBytes(StandardCharsets.UTF_8), "https://example.com");
        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.of(LookupResult.MALICIOUS));
    }

    @Test
    void isRateLimitingEnabledDefaultsToTrue() {
        Assertions.assertThat(provider.isRateLimitingEnabled()).isTrue();
    }

    @Test
    void isAbuseLimitingEnabledDefaultsToTrue() {
        Assertions.assertThat(provider.isAbuseLimitingEnabled()).isTrue();
    }
}
