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

import io.github.bucket4j.Bucket;
import net.foulest.ospreyproxy.ProxyHandler;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Common interface for all upstream URL-checking providers.
 * <p>
 * Each provider implements only the methods relevant to its API style.
 * POST providers override {@link #buildBody}; GET providers override
 * {@link #getMethod} and {@link #buildRequestUrl}.
 * All validation and proxying logic lives in {@link ProxyHandler#proxyRequest}.
 */
public interface Provider {

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

    /**
     * Gets the invalid request bucket for the given IP address, creating it if it doesn't exist.
     *
     * @param ip The IP address to get the invalid request bucket for.
     * @return The Bucket object representing the invalid request limit for the given IP.
     */
    @NonNull Bucket getInvalidRequestBucket(@NonNull String ip);

    /**
     * Checks if the given IP address is currently blocked due to exceeding the burst rate limit.
     *
     * @param ip The IP address to check for burst block status.
     * @return True if the IP is currently blocked for burst violations, false otherwise.
     */
    boolean isBurstBlocked(@NonNull String ip);

    /**
     * Checks if the given IP address is currently blocked due to exceeding the sustained rate limit.
     *
     * @param ip The IP address to check for sustained block status.
     * @return True if the IP is currently blocked for sustained violations, false otherwise.
     */
    boolean isSustainedBlocked(@NonNull String ip);

    /**
     * Checks if the given IP address is currently blocked due to making invalid requests.
     *
     * @param ip The IP address to check for invalid request block status.
     * @return True if the IP is currently blocked for invalid requests, false otherwise.
     */
    boolean isInvalidRequestBlocked(@NonNull String ip);

    /**
     * Blocks the given IP address due to a burst rate limit
     * violation by adding it to the burst blocked cache.
     *
     * @param ip The IP address to block for burst violations.
     */
    void blockBurst(@NonNull String ip);

    /**
     * Blocks the given IP address due to a sustained rate limit
     * violation by adding it to the sustained blocked cache.
     *
     * @param ip The IP address to block for sustained violations.
     */
    void blockSustained(@NonNull String ip);

    /**
     * Blocks the given IP address due to an invalid request by
     * adding it to the invalid request blocked cache.
     *
     * @param ip The IP address to block for invalid requests.
     */
    void blockInvalidRequest(@NonNull String ip);

    /**
     * Returns a stable, non-PII violator ID for the given IP address.
     * The ID is an incrementing integer assigned on first violation and
     * reused on subsequent violations by the same IP within this session.
     * Resets on restart, cannot be reversed to an IP address.
     *
     * @param ip The hashed IP address to get or assign a violator ID for.
     * @return A short numeric string identifying this violator (e.g., "#42").
     */
    @NonNull String getViolatorId(@NonNull String ip);
}
