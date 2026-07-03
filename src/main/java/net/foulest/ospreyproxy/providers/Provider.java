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
import net.foulest.ospreyproxy.result.LookupVerdict;
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
     * The default implementation returns {@link #getApiUrl()} unchanged, which is correct for
     * POST providers that send the target as a request body field.
     * GET providers that encode the target into the path should override this method.
     *
     * @param url The validated URL to lookup.
     * @return The full upstream request URL.
     */
    default @NonNull String buildRequestUrl(@NonNull String url) {
        return getApiUrl();
    }

    /**
     * Whether to strip the URL down to a hostname before forwarding to this provider, removing
     * the path and query string. Defaults to {@code false}. Override for providers that only accept a host.
     *
     * @return {@code true} if only the bare host should be forwarded, {@code false} otherwise.
     */
    default boolean isStripToHost() {
        return false;
    }

    /**
     * Whether to strip the URL down to its bare registrable domain (eTLD+1) before forwarding to
     * this provider, removing the path, query string, and any subdomains. For example,
     * {@code https://test.google.com/test} is reduced to {@code google.com}. The reduction is
     * driven by the Public Suffix List, so multi-level suffixes are handled correctly (e.g.
     * {@code foo.example.co.uk} becomes {@code example.co.uk}, not {@code co.uk}).
     * <p>
     * This is a stronger form of {@link #isStripToHost()}: it also collapses subdomains, so a
     * provider that returns {@code true} here is always treated as host-keyed. Defaults to
     * {@code false}. Override for providers that only accept a bare host.
     *
     * @return {@code true} if only the bare registrable domain should be forwarded, {@code false} otherwise.
     */
    default boolean isStripToBareHost() {
        return false;
    }

    /**
     * Whether this provider should use the classic HTTP/1.1 client instead of the shared HTTP/2 DNS client.
     * Defaults to {@code false}. Override for providers whose upstream works more reliably with the old client.
     *
     * @return {@code true} to use the classic HTTP/1.1 client, {@code false} to use the shared HTTP/2 client.
     */
    default boolean isUsingOldHTTP() {
        return false;
    }

    /**
     * Whether an upstream HTTP 404 should be treated as a valid lookup result rather than an error.
     * <p>
     * Some providers (e.g. BforeAI) return 404 with a message body when the requested URL is simply
     * not present in their threat database. For those providers a 404 is not a failure: it is a clean
     * "not found" answer that should be passed to {@link #interpretAll} and cached like any 200 response.
     * Defaults to {@code false}, so 404 is treated as an error for every other provider.
     *
     * @return {@code true} if a 404 response body should be interpreted and cached, {@code false} otherwise.
     */
    default boolean isNotFoundValidResponse() {
        return false;
    }

    /**
     * Interprets the raw upstream response bytes and returns a single {@link LookupResult}.
     * <p>
     * This is the common case: most providers report exactly one verdict per URL.
     * Single-result API providers (e.g. PrecisionSec, ChainPatrol) override this.
     * Providers whose upstream can report several independent categories for one URL
     * (e.g. AlphaMountain) override {@link #interpretAll} instead and leave this alone.
     * DNS providers use a separate {@link AbstractDNSProvider#interpret} contract.
     * <p>
     * The default implementation returns {@link LookupResult#FAILED}, which is safe
     * for DNS providers since they never reach {@code executeUpstream}.
     *
     * @param responseBytes The validated, non-empty upstream response bytes.
     * @param url The normalized URL that was checked, for logging context.
     * @return The {@link LookupResult} for this lookup.
     */
    default @NonNull LookupResult interpret(byte @NonNull [] responseBytes, @NonNull String url) {
        return LookupResult.FAILED;
    }

    /**
     * Interprets the raw upstream response bytes and returns a {@link LookupVerdict}, which may
     * carry one or several {@link LookupResult}s.
     * <p>
     * This is the verdict-level entry point used by the proxy pipeline (the result cache and the
     * HTTP response are both keyed on {@link LookupVerdict}). The default implementation simply
     * wraps {@link #interpret}, so single-result providers need only implement {@code interpret}
     * and get a one-element verdict for free.
     * <p>
     * Override this method directly only when a single URL can legitimately map to multiple
     * independent categories at once (e.g. AlphaMountain reporting that a host is both newly
     * registered and malicious). Such providers should not also override {@link #interpret}.
     *
     * @param responseBytes The validated, non-empty upstream response bytes.
     * @param url The normalized URL that was checked, for logging context.
     * @return The {@link LookupVerdict} for this lookup; never empty.
     */
    default @NonNull LookupVerdict interpretAll(byte @NonNull [] responseBytes, @NonNull String url) {
        return LookupVerdict.of(interpret(responseBytes, url));
    }

    /**
     * Whether rate limiting is enabled for this provider.
     * Returns {@code true} by default. Override to return {@code false} to disable all
     * rate limiting checks ({@link #isBurstBlocked}, {@link #isSustainedBlocked})
     * and all {@code blockX} methods become no-ops.
     *
     * @return {@code true} if rate limiting is active, {@code false} to bypass it entirely.
     */
    default boolean isRateLimitingEnabled() {
        return true;
    }

    /**
     * Whether abuse limiting is enabled for this provider.
     * Returns {@code true} by default. Override to return {@code false} to disable all
     * abuse limiting checks ({@link #isInvalidRequestBlocked}) and all
     * {@code blockInvalidRequest} methods become no-ops.
     *
     * @return {@code true} if abuse limiting is active, {@code false} to bypass it entirely
     */
    default boolean isAbuseLimitingEnabled() {
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
     * Checks if the given IP address is currently blocked due to too many invalid requests.
     *
     * @param ip The IP address to lookup for invalid-request block status.
     * @return {@code true} if the IP is currently blocked for invalid-request violations, {@code false} otherwise.
     */
    boolean isInvalidRequestBlocked(@NonNull String ip);

    /**
     * Records a burst-rate-limit violation for the given IP.
     *
     * @param ip The IP address to block for burst violations.
     */
    void blockBurst(@NonNull String ip);

    /**
     * Records a sustained-rate-limit violation for the given IP.
     *
     * @param ip The IP address to block for sustained violations.
     */
    void blockSustained(@NonNull String ip);

    /**
     * Records an invalid-request violation for the given IP.
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
