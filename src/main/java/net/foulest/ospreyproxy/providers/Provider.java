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
import net.foulest.ospreyproxy.result.LookupResult;
import org.apache.hc.core5.http.Method;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Common interface for all upstream URL-checking providers.
 * <p>
 * Each provider implements only the methods relevant to its API style.
 * POST providers override {@link #buildBody}; GET providers override
 * {@link #getMethod} and {@link #buildRequestUrl}.
 * DNS providers extend {@link AbstractDNSProvider} and implement {@code interpret}.
 */
public interface Provider {

    /**
     * A human-readable name for this provider, used in logging and error messages.
     *
     * @return The display name of the provider.
     */
    @NonNull
    String getDisplayName();

    /**
     * A unique endpoint name for this provider, used in configuration and routing.
     *
     * @return The unique endpoint name of the provider.
     */
    @NonNull
    String getEndpointName();

    /**
     * Whether the provider is enabled.
     *
     * @return {@code true} if the provider is enabled, {@code false} otherwise.
     */
    boolean isEnabled();

    /**
     * The base upstream API URL.
     *
     * @return The upstream API URL.
     */
    default @NonNull String getApiUrl() {
        return "";
    }

    /**
     * The base upstream API key.
     *
     * @return The upstream API key.
     */
    default @NonNull String getApiKey() {
        return "";
    }

    /**
     * HTTP method to use for the upstream request.
     *
     * @return The HTTP method to use (e.g., GET, POST).
     */
    default @NonNull Method getMethod() {
        return Method.GET;
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
     * Returns {@code null} for GET providers.
     *
     * @param url The validated URL to lookup.
     * @return The request body map, or {@code null} for GET providers.
     */
    default @Nullable Map<String, Object> buildBody(@NonNull String url) {
        return null;
    }

    /**
     * Builds the full upstream request URL.
     * For POST providers this defaults to {@link #getApiUrl()}.
     * For GET providers this should encode the target URL into the path.
     *
     * @param url The validated URL to lookup.
     * @return The full upstream request URL.
     */
    default @NonNull String buildRequestUrl(@NonNull String url) {
        return getApiUrl();
    }

    /**
     * Whether to strip the URL down to a bare hostname before forwarding to this provider.
     * Providers like PrecisionSec only accept a domain with no scheme, path, query, or fragment.
     * Defaults to {@code false}.
     *
     * @return {@code true} if only the bare host should be forwarded, {@code false} otherwise.
     */
    default boolean stripToHost() {
        return false;
    }

    /**
     * Interprets the raw upstream response bytes and returns a {@link LookupResult}.
     * <p>
     * API providers (e.g. AlphaMountain, PrecisionSec) override this to parse their
     * upstream JSON and map it to a result. DNS providers use a separate
     * {@link AbstractDNSProvider#interpret} contract and do not override this method.
     * <p>
     * The default implementation returns {@link LookupResult#FAILED}, which is safe
     * for DNS providers since they never reach {@code executeUpstream}.
     *
     * @param responseBytes The validated, non-empty upstream response bytes.
     * @param normalizedUrl The normalized URL that was checked, for logging context.
     * @return The {@link LookupResult} for this lookup.
     */
    default @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String normalizedUrl) {
        return LookupResult.FAILED;
    }

    @NonNull LookupResult cachedLookup(@NonNull String lookupStr);

    /**
     * Whether rate limiting is enabled for this provider.
     * Returns {@code true} by default. Override to return {@code false} to disable all
     * rate limiting checks ({@link #isBurstBlocked}, {@link #isSustainedBlocked},
     * {@link #isInvalidRequestBlocked}, and all {@code blockX} methods become no-ops).
     *
     * @return {@code true} if rate limiting is active, {@code false} to bypass it entirely.
     */
    default boolean isRateLimitingEnabled() {
        return true;
    }

    /**
     * Gets the burst rate limit bucket for the given IP address, creating it if it doesn't exist.
     *
     * @param ip The IP address to get the burst bucket for.
     * @return The {@link Bucket} object representing the burst rate limit for the given IP.
     */
    @NonNull Bucket getBurstBucket(@NonNull String ip);

    /**
     * Gets the sustained rate limit bucket for the given IP address, creating it if it doesn't exist.
     *
     * @param ip The IP address to get the sustained bucket for.
     * @return The {@link Bucket} object representing the sustained rate limit for the given IP.
     */
    @NonNull Bucket getSustainedBucket(@NonNull String ip);

    /**
     * Gets the invalid request bucket for the given IP address, creating it if it doesn't exist.
     *
     * @param ip The IP address to get the invalid request bucket for.
     * @return The {@link Bucket} object representing the invalid request limit for the given IP.
     */
    @NonNull Bucket getInvalidRequestBucket(@NonNull String ip);

    /**
     * Checks if the given IP address is currently blocked due to exceeding the burst rate limit.
     *
     * @param ip The IP address to lookup for burst block status.
     * @return {@code true} if the IP is currently blocked for burst violations, {@code false} otherwise.
     */
    boolean isBurstBlocked(@NonNull String ip);

    /**
     * Checks if the given IP address is currently blocked due to exceeding the sustained rate limit.
     *
     * @param ip The IP address to lookup for sustained block status.
     * @return {@code true} if the IP is currently blocked for sustained violations, {@code false} otherwise.
     */
    boolean isSustainedBlocked(@NonNull String ip);

    /**
     * Checks if the given IP address is currently blocked due to making invalid requests.
     *
     * @param ip The IP address to lookup for invalid request block status.
     * @return {@code true} if the IP is currently blocked for invalid requests, {@code false} otherwise.
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
