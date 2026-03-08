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
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Map;

/**
 * Common interface for all upstream URL-checking providers.
 * <p>
 * Each provider implements only the methods relevant to its API style.
 * POST providers override {@link #buildBody}; GET providers override
 * {@link #getMethod} and {@link #buildRequestUrl}.
 * All validation and proxying logic lives in ProxyHandler.proxyRequest().
 */
public interface Provider {

    int DEFAULT_IP_BURST_CAPACITY = 11;

    /**
     * A human-readable name for this provider, used in logging and error messages.
     *
     * @return The display name of the provider.
     */
    @NonNull
    String getName();

    /**
     * The base upstream API URL.
     *
     * @return The upstream API URL.
     */
    @NonNull
    String getApiUrl();

    /**
     * HTTP method to use for the upstream request.
     * Defaults to POST. Override to return "GET" for GET-based providers.
     *
     * @return The HTTP method string.
     */
    default @NonNull String getMethod() {
        return "POST";
    }

    /**
     * Additional headers to include in the upstream request.
     * Override to inject API keys or other provider-specific headers.
     *
     * @return A map of header name to header value.
     */
    default @NonNull Map<String, String> getHeaders() {
        return Map.of();
    }

    /**
     * Builds the request body for POST providers.
     * Returns null for GET providers.
     *
     * @param url The validated URL to check.
     * @return The request body map, or null for GET providers.
     */
    default @Nullable Map<String, Object> buildBody(@NonNull String url) {
        return null;
    }

    /**
     * Builds the full upstream request URL.
     * For POST providers this defaults to {@link #getApiUrl()}.
     * For GET providers this should encode the target URL into the path.
     *
     * @param url The validated URL to check.
     * @return The full upstream request URL.
     */
    default @NonNull String buildRequestUrl(@NonNull String url) {
        return getApiUrl();
    }

    /**
     * Gets the capacity for the burst rate limit bucket.
     * This is the maximum number of requests allowed per IP address in the burst rate limit window.
     *
     * @return The capacity for the burst rate limit bucket.
     */
    int getBurstCapacity();

    /**
     * Gets the capacity for the sustained rate limit bucket.
     * This is the maximum number of requests allowed per IP address in the sustained rate limit window.
     *
     * @return The capacity for the sustained rate limit bucket.
     */
    int getSustainedCapacity();

    /**
     * Duration for burst rate limiting. This is the interval at which the burst bucket refills.
     *
     * @return A Duration object representing the burst rate limit refill interval.
     */
    @NonNull Duration getBurstDuration();

    /**
     * Duration for sustained rate limiting. This is the interval at which the sustained bucket refills.
     *
     * @return A Duration object representing the sustained rate limit refill interval.
     */
    @NonNull Duration getSustainedDuration();

    /**
     * Constructs the Bandwidth object for burst rate limiting based on the provider's parameters.
     *
     * @return A Bandwidth instance configured for burst rate limiting according to the provider's settings.
     */
    @NonNull Bandwidth getBurstBandwidth();

    /**
     * Constructs the Bandwidth object for sustained rate limiting based on the provider's parameters.
     *
     * @return A Bandwidth instance configured for sustained rate limiting according to the provider's settings.
     */
    @NonNull Bandwidth getSustainedBandwidth();

    /**
     * Provides the Caffeine cache object for burst rate limit buckets.
     *
     * @return A Caffeine Cache instance for burst rate limit buckets.
     */
    @NonNull Cache<String, Bucket> getBurstBucketCache();

    /**
     * Provides the Caffeine cache object for sustained rate limit buckets.
     *
     * @return A Caffeine Cache instance for sustained rate limit buckets.
     */
    @NonNull Cache<String, Bucket> getSustainedBucketCache();

    /**
     * Gets the burst rate limit bucket for the given IP address, creating it if it doesn't exist.
     *
     * @param ip The IP address to get the burst bucket for.
     * @return The Bucket object representing the burst rate limit for the given IP.
     */
    @NonNull Bucket getBurstBucket(@NonNull String ip);

    /**
     * Gets the sustained rate limit bucket for the given IP address, creating it if it doesn't exist.
     *
     * @param ip The IP address to get the sustained bucket for.
     * @return The Bucket object representing the sustained rate limit for the given IP.
     */
    @NonNull Bucket getSustainedBucket(@NonNull String ip);
}
