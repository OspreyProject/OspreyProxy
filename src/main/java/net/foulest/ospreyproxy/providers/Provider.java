package net.foulest.ospreyproxy.providers;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Common interface for all upstream URL-checking providers.
 * <p>
 * Each provider implements only the methods relevant to its API style.
 * POST providers override {@link #buildBody}; GET providers override
 * {@link #getMethod} and {@link #buildRequestUrl}.
 * All validation and proxying logic lives in ProxyHandler.proxyRequest().
 */
@FunctionalInterface
public interface Provider {

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
}
