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

import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.HttpClientFactory;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.dns.Accept;
import net.foulest.ospreyproxy.util.dns.DNSUtil;
import net.foulest.ospreyproxy.util.dns.DNSFormat;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Abstract base class for DNS-over-HTTPS filtering providers.
 * <p>
 * Owns the shared HTTP/2 client and the standard fetch-and-interpret pipeline.
 * Subclasses implement {@link #interpret} to declare their own response-to-result
 * mappings without touching transport or logging.
 */
@Slf4j
public abstract class AbstractDNSProvider extends AbstractProvider {

    // HTTP/2 client shared across all DNS providers.
    // Multiplexing handles max conn. total and max conn. per route.
    // 5s connect, 5s connection-request, 5s response, 10s operation timeout.
    private static final CloseableHttpClient FILTERING_CLIENT =
            HttpClientFactory.createHttp2Client(5, 5, 5, 10);

    /**
     * Checks a hostname against this provider's DNS filter.
     * <p>
     * Handles the full fetch-and-interpret cycle; subclasses only implement {@link #interpret}.
     *
     * @param host The hostname to lookup, e.g. "example.com".
     * @return The {@link LookupResult} for this host.
     */
    @SuppressWarnings("NestedMethodCall")
    public final LookupResult lookup(@NonNull String host) {
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
                    yield interpret(response, null, host);
                }
                case NAME_JSON, PATH_JSON -> {
                    Map<String, Object> response = fetchDnsJson(encodedUrl, displayName);

                    if (response.isEmpty()) {
                        log.warn("[{}] Empty response returned for '{}'", displayName, host);
                        yield LookupResult.FAILED;
                    }
                    yield interpret(null, response, host);
                }
            };
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to lookup host '{}': {} ({})",
                    displayName, host, e.getMessage(), e.getClass().getName(), e);
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
     * @param rawBytes     The raw DNS wire-format response, or {@code null} for JSON providers.
     * @param jsonResponse The parsed DNS JSON response map, or {@code null} for wire-format providers.
     * @param host         The hostname that was checked, for logging purposes.
     * @return The {@link LookupResult} for this host.
     */
    protected abstract LookupResult interpret(byte @Nullable [] rawBytes,
                                              @Nullable Map<String, Object> jsonResponse,
                                              @NonNull String host);

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
    private static byte @Nullable [] fetchDnsMessage(@NonNull String url,
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
    private static @NonNull Map<String, Object> fetchDnsJson(@NonNull String url, @NonNull String displayName) {
        byte[] body = fetchBytes(url, Accept.DNS_JSON, displayName);

        if (body == null) {
            return Map.of();
        }

        try {
            return JacksonUtil.MAPPER.readValue(body, JacksonUtil.MAP_TYPE_OBJECT);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to parse DNS JSON response: {}", displayName, e.getMessage());
            return Map.of();
        }
    }

    /**
     * Fetches raw bytes from the given URL, validating HTTP status and Content-Type.
     *
     * @param url               The full URL to fetch.
     * @param accept            The Accept header value (also used for Content-Type validation).
     * @param displayName       The provider name for logging.
     * @return The raw response bytes, or {@code null} on failure.
     */
    @SuppressWarnings("NestedMethodCall")
    private static byte @Nullable [] fetchBytes(@NonNull String url,
                                                @NonNull String accept,
                                                @NonNull String displayName) {
        try {
            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", accept);

            return FILTERING_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.warn("[{}] Unexpected status {} for URL '{}'", displayName, statusCode, url);
                    return null;
                }

                String contentType = getContentType(response);

                if (!contentType.contains(accept)) {
                    log.warn("[{}] Unexpected Content-Type '{}' for URL '{}'", displayName, contentType, url);
                    return null;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity, 64 * 1024);

                if (body == null || body.length == 0) {
                    log.warn("[{}] Empty response body for URL '{}'", displayName, url);
                    return null;
                }

                return body;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] HTTP fetch failed for URL '{}': {} ({})",
                    displayName, url, e.getMessage(), e.getClass().getName());
            return null;
        }
    }

    /**
     * Extracts the Content-Type header value from the response.
     *
     * @param response The response to extract the Content-Type from.
     * @return The Content-Type as a String.
     */
    private static @NonNull String getContentType(@NonNull ClassicHttpResponse response) {
        Header header = response.getFirstHeader("Content-Type");
        return header != null ? header.getValue() : "";
    }
}
