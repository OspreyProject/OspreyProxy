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

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.services.CircuitBreakerService;
import net.foulest.ospreyproxy.services.MetricsService;
import net.foulest.ospreyproxy.util.HttpClientFactory;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.dns.Accept;
import net.foulest.ospreyproxy.util.dns.DNSFormat;
import net.foulest.ospreyproxy.util.dns.DNSUtil;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.MessageHeaders;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Abstract base class for DNS providers, handling the common logic of fetching and interpreting DNS responses.
 */
@Slf4j
@AllArgsConstructor
public abstract class AbstractDNSProvider extends AbstractProvider {

    // Shared HTTP/2 client across DNS providers.
    private static final CloseableHttpClient FILTERING_CLIENT =
            HttpClientFactory.createHttp2Client(5, 5, 5, 10);

    // Shared classic HTTP/1.1 client for providers that explicitly opt out of the HTTP/2 client.
    private static final CloseableHttpClient LEGACY_FILTERING_CLIENT =
            HttpClientFactory.createHttp1Client(5, 5, 10);

    // Injected by Spring into each concrete @Component subclass
    private final MetricsService metricsService;
    private final CircuitBreakerService circuitBreakerService;

    private @NonNull CloseableHttpClient getDnsHttpClient() {
        return useOldHTTP() ? LEGACY_FILTERING_CLIENT : FILTERING_CLIENT;
    }

    /**
     * Performs a cached lookup for the given host, using the provider's DNS filter.
     *
     * @param lookupStr The validated string to look up (host or URL).
     * @return The {@link LookupResult} for this host, from cache if available or freshly looked up if not.
     */
    @Override
    public final @NonNull LookupResult cachedLookup(@NonNull String lookupStr) {
        String displayName = getDisplayName();

        // Short-circuit if the circuit breaker is open (too many recent failures)
        if (circuitBreakerService.isOpen(displayName)) {
            return LookupResult.RATE_LIMITED;
        }

        LookupResult cached = getCachedResult(lookupStr);

        if (cached != null) {
            metricsService.recordCacheHit();
            return cached;
        }

        metricsService.recordCacheMiss();
        LookupResult result = lookup(lookupStr);

        putCachedResult(lookupStr, result);
        return result;
    }

    /**
     * Checks a hostname against this provider's DNS filter.
     * <p>
     * Handles the full fetch-and-interpret cycle; subclasses only implement {@link #interpret}.
     *
     * @param host The hostname to lookup, e.g. "example.com".
     * @return The {@link LookupResult} for this host.
     */
    @SuppressWarnings("NestedMethodCall")
    private LookupResult lookup(@NonNull String host) {
        String displayName = getDisplayName();
        String url = getApiUrl();
        DNSFormat format = getDnsFormat();

        try {
            String encodedUrl = switch (format) {
                case NAME_MESSAGE, NAME_JSON -> url + DNSUtil.encodeHostParam(host);
                case PATH_MESSAGE, PATH_JSON -> url + DNSUtil.buildBase64Query(host);
            };

            return switch (format) {
                case NAME_MESSAGE, PATH_MESSAGE -> {
                    byte[] response = fetchDnsMessage(encodedUrl, displayName);

                    if (response == null) {
                        yield LookupResult.FAILED;
                    }
                    yield interpret(response, (Map<String, Object>) null);
                }

                case NAME_JSON, PATH_JSON -> {
                    Map<String, Object> response = fetchDnsJson(encodedUrl, displayName);

                    if (response.isEmpty()) {
                        log.warn("[{}] Empty response returned", displayName);
                        yield LookupResult.FAILED;
                    }
                    yield interpret(null, response);
                }
            };
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to perform lookup ({})", displayName, e.getClass().getName(), e);
            return LookupResult.FAILED;
        }
    }

    /**
     * Specifies the DNS format used by this provider, which determines how the request is built
     * and how the response is interpreted. The default is {@link DNSFormat#PATH_MESSAGE}
     * which works for most providers, but some (e.g. Control D Family) require {@link DNSFormat#NAME_MESSAGE}
     * or {@link DNSFormat#NAME_JSON}.
     * <p>
     * The format determines whether the hostname is encoded as a query parameter or as a base64-encoded DNS message in the path,
     * and whether the response is expected as raw bytes or as JSON.
     *
     * @return The {@link DNSFormat} used by this provider.
     */
    protected DNSFormat getDnsFormat() {
        return DNSFormat.PATH_MESSAGE;
    }

    /**
     * Interprets a DNS response and returns the appropriate {@link LookupResult}.
     * <p>
     * Exactly one of {@code rawBytes} or {@code jsonResponse} will be non-null,
     * based on {@link #getDnsFormat()}.
     *
     * @param rawBytes The raw DNS wire-format response, or {@code null} for JSON providers.
     * @param jsonResponse The parsed DNS JSON response map, or {@code null} for wire-format providers.
     * @return The {@link LookupResult} for this host.
     */
    protected abstract LookupResult interpret(byte @Nullable [] rawBytes,
                                              @Nullable Map<String, Object> jsonResponse);

    /**
     * Extracts the {@code Comment} field from a Cloudflare-style DNS JSON response as a single string.
     * The field may be a {@link String} or a {@link List} of strings; both are handled.
     *
     * @param jsonResponse The parsed DNS JSON response map.
     * @return The comment string, or an empty string if absent or of an unexpected type.
     */
    protected static @NonNull String extractComment(@NonNull Map<String, Object> jsonResponse) {
        Object comment = jsonResponse.get("Comment");

        if (comment == null) {
            return "";
        }

        return switch (comment) {
            case List<?> list -> list.stream().map(Object::toString).collect(Collectors.joining(" "));
            case String s -> s;
            default -> "";
        };
    }

    /**
     * Fetches a raw DNS wire-format message from the given URL.
     *
     * @param url                 The full URL to fetch.
     * @param displayName         The provider name for logging.
     * @return The raw response bytes, or {@code null} on failure.
     */
    private byte @Nullable [] fetchDnsMessage(@NonNull String url,
                                              @NonNull String displayName) {
        return fetchBytes(url, Accept.DNS_MESSAGE, displayName);
    }

    /**
     * Fetches a DNS JSON response from the given URL and parses it into a map.
     *
     * @param url         The full URL to fetch.
     * @param displayName The provider name for logging.
     * @return A map representing the parsed JSON response, or an empty map on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private @NonNull Map<String, Object> fetchDnsJson(@NonNull String url, @NonNull String displayName) {
        byte[] body = fetchBytes(url, Accept.DNS_JSON, displayName);

        if (body == null) {
            return Map.of();
        }

        try {
            return JacksonUtil.MAPPER.readValue(body, JacksonUtil.MAP_TYPE_OBJECT);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to parse DNS JSON response ({})", displayName, e.getClass().getName());
            return Map.of();
        }
    }

    /**
     * Fetches raw bytes from the given URL, validating HTTP status and Content-Type.
     *
     * @param url The full URL to fetch.
     * @param accept The Accept header value (also used for Content-Type validation).
     * @param displayName The provider name for logging.
     * @return The raw response bytes, or {@code null} on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private byte @Nullable [] fetchBytes(@NonNull String url,
                                         @NonNull CharSequence accept,
                                         @NonNull String displayName) {
        long startNanos = System.nanoTime();
        CloseableHttpClient client = getDnsHttpClient();

        try {
            ClassicHttpRequest request = new HttpGet(url);
            request.addHeader("Accept", accept);

            return client.execute(request, response -> {
                int statusCode = response.getCode();
                String contentType = getContentType(response);

                if (statusCode != 200) {
                    if (statusCode == 429) {
                        circuitBreakerService.recordFailure(displayName, 0L, new RuntimeException("HTTP 429"));
                    } else if (statusCode >= 500) {
                        circuitBreakerService.recordFailure(displayName, 0L, new RuntimeException("HTTP " + statusCode));
                    } else {
                        log.warn("[{}] Unexpected status code: {}", displayName, statusCode);
                    }
                    return null;
                }

                if (!contentType.contains(accept)) {
                    log.warn("[{}] Unexpected Content-Type '{}'", displayName, contentType);
                    return null;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity, 64 << 10);
                long totalElapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;

                if (body == null || body.length == 0) {
                    log.warn("[{}] Empty response body after {} ms", displayName, totalElapsedMs);
                    return null;
                }
                return body;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] HTTP fetch failed: {} ({})",
                    displayName, e.getMessage(), e.getClass().getName());
            return null;
        }
    }

    /**
     * Extracts the Content-Type header value from the response.
     *
     * @param response The response to extract the Content-Type from.
     * @return The Content-Type as a String.
     */
    private static @NonNull String getContentType(@NonNull MessageHeaders response) {
        Header header = response.getFirstHeader("Content-Type");
        return header != null ? header.getValue() : "";
    }
}
