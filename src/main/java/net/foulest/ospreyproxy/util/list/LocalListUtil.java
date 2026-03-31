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
package net.foulest.ospreyproxy.util.list;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.HttpClientFactory;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Utility class for managing local lists of domains fetched from external providers.
 */
@Slf4j
@Component
public final class LocalListUtil {

    // HTTP/2 client for list fetches.
    // 30s connect, 30s connection-request, 30s response, 35s operation timeout.
    private static final CloseableHttpClient FETCH_CLIENT =
            HttpClientFactory.createHttp2Client(30, 30, 30, 35);

    // Scheduler for periodic list refreshes
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "local-list-refresh");
        thread.setDaemon(true);
        return thread;
    });

    // Runtime state per descriptor, keyed by descriptor identity
    private static final Map<Descriptor, AtomicReference<ListSnapshot>> stateMap = new EnumMap<>(Descriptor.class);

    // Descriptors keyed by endpoint name for O(1) routing in ProxyHandler
    private static final Map<String, Descriptor> descriptorsByEndpointName;

    static {
        Map<String, Descriptor> map = new HashMap<>();
        for (Descriptor descriptor : Descriptor.values()) {
            map.put(descriptor.endpointName, descriptor);
        }
        descriptorsByEndpointName = Collections.unmodifiableMap(map);
    }

    @PostConstruct
    public void init() {
        for (Descriptor descriptor : Descriptor.values()) {
            stateMap.put(descriptor, new AtomicReference<>(ListSnapshot.EMPTY));
        }

        for (Descriptor descriptor : Descriptor.values()) {
            // Immediate fetch on startup, then repeat at this descriptor's configured interval
            scheduler.scheduleWithFixedDelay(
                    () -> fetchAndUpdate(descriptor),
                    0L,
                    descriptor.refreshIntervalSeconds,
                    TimeUnit.SECONDS
            );
        }
    }

    @PreDestroy
    public void destroy() {
        scheduler.shutdownNow();
    }

    /**
     * Finds the descriptor corresponding to the given endpoint name, or returns {@code null} if no match is found.
     *
     * @param endpointName The endpoint name to look up, e.g. "quad9".
     * @return The matching {@link Descriptor}, or {@code null} if no match is found.
     */
    public static @Nullable Descriptor findByEndpointName(@NonNull String endpointName) {
        return descriptorsByEndpointName.get(endpointName);
    }

    /**
     * Looks up the given host in the live set for the specified descriptor, returning the appropriate {@link LookupResult}.
     *
     * @param descriptor The list descriptor to lookup against.
     * @param host The hostname to lookup for listing.
     * @return The {@link LookupResult} for this host: either the descriptor's configured result type if listed,
     *         or {@link LookupResult#ALLOWED} if not listed or if the list has not yet been loaded (fail-open).
     */
    public static @NonNull LookupResult lookupHost(@NonNull Descriptor descriptor, @NonNull String host) {
        AtomicReference<ListSnapshot> ref = stateMap.get(descriptor);

        if (ref == null) {
            return LookupResult.FAILED;
        }

        Set<String> domainSet = ref.get().domainSet();

        if (domainSet == null) {
            log.warn("[{}] List not yet loaded; skipping pending lookup", descriptor.shortName);
            return LookupResult.FAILED;
        }
        return isHostInSet(domainSet, host) ? descriptor.resultType : LookupResult.ALLOWED;
    }

    /**
     * Checks whether the given hostname or any of its ancestor domains (up to but not including
     * the TLD) appears in the given domain set.
     *
     * @param domainSet The set of normalized hostnames to check against.
     * @param host The raw hostname to check.
     * @return {@code true} if the host or any ancestor domain is in the set.
     */
    private static boolean isHostInSet(@NonNull Set<String> domainSet, @NonNull String host) {
        String normalized = host.trim().toLowerCase(Locale.ROOT);

        if (domainSet.contains(normalized)) {
            return true;
        }

        String[] labels = normalized.split("\\.", -1);

        // Walk up the domain tree, checking each parent suffix.
        // Stops before the TLD (must have at least two labels to be meaningful).
        for (int i = 1; i < labels.length - 1; i++) {
            String ancestor = String.join(".", Arrays.copyOfRange(labels, i, labels.length));

            if (domainSet.contains(ancestor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Fetches the list content from the descriptor's URL and updates the live domain set.
     * Sends the stored ETag as {@code If-None-Match} so the server can return 304 Not Modified
     * when the content is unchanged, avoiding a full download.
     *
     * @param descriptor The list descriptor to fetch and update.
     */
    @SuppressWarnings("NestedMethodCall")
    private static void fetchAndUpdate(@NonNull Descriptor descriptor) {
        try {
            ListSnapshot current = stateMap.get(descriptor).get();
            FetchResult result = fetchRaw(descriptor, current.etag());

            if (result != null) {
                applyContent(descriptor, result.rawContent(), result.etag());
            }
        } catch (Exception e) {
            log.warn("[{}] Failed to fetch list update: {} ({})",
                    descriptor.shortName, e.getMessage(), e.getClass().getName());
        }
    }

    /**
     * Fetches the raw content string from the descriptor's URL.
     * <p>
     * If {@code currentEtag} is non-null, it is sent as {@code If-None-Match}. A 304 Not Modified
     * response causes this method to return {@code null}, signaling that the caller should skip
     * the update. A 200 response is read, size-limited to 50 MiB, and returned as a {@link FetchResult}
     * alongside the response ETag (if present). Any other status code is treated as an error.
     *
     * @param descriptor The list descriptor to fetch.
     * @param currentEtag The ETag from the last successful fetch, or {@code null} on first fetch.
     * @return A {@link FetchResult} with the body and ETag, or {@code null} if the server returned 304 Not Modified.
     */
    @SuppressWarnings({"NestedMethodCall", "ProhibitedExceptionDeclared"})
    private static @Nullable FetchResult fetchRaw(@NonNull Descriptor descriptor,
                                                  @Nullable String currentEtag) throws Exception {
        HttpGet request = new HttpGet(descriptor.url);
        request.addHeader("Accept", "application/json, text/plain, */*");

        if (currentEtag != null) {
            request.addHeader("If-None-Match", currentEtag);
        }

        return FETCH_CLIENT.execute(request, response -> {
            int statusCode = response.getCode();

            if (statusCode == 304) {
                return null;
            }

            if (statusCode != 200) {
                throw new IllegalStateException("HTTP " + statusCode);
            }

            String contentType = Optional.ofNullable(response.getFirstHeader("Content-Type"))
                    .map(Header::getValue)
                    .orElse("");

            if (!contentType.contains("application/json") && !contentType.contains("text/")) {
                throw new IllegalStateException("Unexpected Content-Type: " + contentType);
            }

            HttpEntity entity = response.getEntity();
            byte[] body = EntityUtils.toByteArray(entity, 50 * 1024 * 1024);

            if (body == null || body.length == 0) {
                throw new IllegalStateException("Response body was empty");
            }

            String etag = Optional.ofNullable(response.getFirstHeader("ETag"))
                    .map(Header::getValue)
                    .orElse(null);
            return new FetchResult(new String(body, StandardCharsets.UTF_8), etag);
        });
    }

    /**
     * Parses the raw content and updates the live domain set for the given descriptor.
     *
     * @param descriptor The list descriptor to update.
     * @param rawContent The raw content string to parse and apply.
     * @param etag The ETag from the response, or {@code null} if the server did not send one.
     */
    @SuppressWarnings("NestedMethodCall")
    private static void applyContent(@NonNull Descriptor descriptor,
                                     @NonNull String rawContent,
                                     @Nullable String etag) {
        Set<String> newSet;
        try {
            newSet = descriptor.format == Format.TEXT
                    ? parsePlainText(rawContent)
                    : parseJson(rawContent);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to parse list; keeping current: {} ({})",
                    descriptor.shortName, e.getMessage(), e.getClass().getName());
            return;
        }

        // Atomically swap in the new immutable snapshot
        stateMap.get(descriptor).set(new ListSnapshot(newSet, etag));
    }

    /**
     * Parses JSON content into a set of hostnames.
     * Expects a JSON array of strings. Null entries and empty strings are ignored.
     * Leading/trailing whitespace is trimmed, and all entries are normalized to lower-case.
     *
     * @param rawJson The raw JSON content from the list endpoint.
     * @return A set of hostnames.
     */
    @SuppressWarnings("NestedMethodCall")
    private static @NonNull Set<String> parseJson(@NonNull String rawJson) {
        List<String> parsed = JacksonUtil.MAPPER.readValue(rawJson, JacksonUtil.LIST_TYPE);

        if (parsed == null) {
            throw new IllegalArgumentException("Expected a JSON array but got null");
        }

        Set<String> set = HashSet.newHashSet(parsed.size() * 2);

        for (String entry : parsed) {
            if (entry != null && !entry.isEmpty()) {
                set.add(entry.trim().toLowerCase(Locale.ROOT));
            }
        }
        return set;
    }

    /**
     * Parses plain text content into a set of hostnames.
     * Lines starting with '#' and blank lines are ignored as comments.
     * For lines in hosts file format (e.g. "127.0.0.1"), only the part after the first tab is considered.
     * Leading "www." is stripped and all entries are normalized to lower-case.
     *
     * @param rawText The raw text content from the list endpoint.
     * @return A set of hostnames.
     */
    private static @NonNull Set<String> parsePlainText(@NonNull String rawText) {
        Set<String> set = new HashSet<>();

        for (String line : rawText.split("\\R", -1)) {
            String trimmed = line.trim();

            // Skip blank lines and comment lines
            if (trimmed.isEmpty() || trimmed.charAt(0) == '#') {
                continue;
            }

            // Handle hosts file format (e.g. "127.0.0.1\thostname.com")
            int tabIndex = trimmed.indexOf('\t');
            String entry = tabIndex == -1 ? trimmed : trimmed.substring(tabIndex + 1).trim();

            // Strip leading www. and normalize to lower-case
            String normalized = entry.toLowerCase(Locale.ROOT);
            if (normalized.startsWith("www.")) {
                normalized = normalized.substring(4);
            }

            if (!normalized.contains(" ") && normalized.contains(".")) {
                set.add(normalized);
            }
        }
        return set;
    }
}
