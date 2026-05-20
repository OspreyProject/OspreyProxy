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
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;

import java.io.*;
import java.net.URI;
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
@SuppressWarnings("NestedMethodCall")
public final class LocalListUtil {

    // HTTP/2 client for list fetches.
    // 30s connect, 30s connection-request, 30s response, 35s operation timeout.
    private static final CloseableHttpClient FETCH_CLIENT =
            HttpClientFactory.createHttp2Client(30, 30, 30, 35);

    // Constants for parsing limits to prevent OOM or DoS from unexpectedly large lists
    private static final int MAX_LIST_BYTES = 16 * 1024 * 1024;
    private static final int MAX_DOMAINS = 1_000_000;
    private static final int MAX_LINE_CHARS = 1024;
    private static final int MAX_DOMAIN_CHARS = 253;

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
            map.put(descriptor.getEndpointName(), descriptor);
        }

        descriptorsByEndpointName = Collections.unmodifiableMap(map);
    }

    /**
     * Initializes the state map and starts the periodic refresh tasks for each descriptor.
     */
    @PostConstruct
    public void init() {
        for (Descriptor descriptor : Descriptor.values()) {
            stateMap.put(descriptor, new AtomicReference<>(ListSnapshot.EMPTY));

            // Immediate fetch on startup, then repeat at this descriptor's configured interval
            scheduler.scheduleWithFixedDelay(
                    () -> fetchAndUpdate(descriptor),
                    0L,
                    descriptor.getRefreshIntervalSeconds(),
                    TimeUnit.SECONDS
            );
        }
    }

    /**
     * Shuts down the scheduler and HTTP client on application shutdown.
     */
    @PreDestroy
    public void destroy() {
        scheduler.shutdownNow();

        try {
            FETCH_CLIENT.close();
        } catch (IOException e) {
            log.warn("Failed to close local-list HTTP client: {} ({})", e.getMessage(), e.getClass().getName());
        }
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
            log.warn("[{}] List not yet loaded; skipping pending lookup", descriptor.getShortName());
            return LookupResult.FAILED;
        }
        return isHostInSet(domainSet, host) ? descriptor.getResultType() : LookupResult.ALLOWED;
    }

    /**
     * Looks up the given URL (full path) in the live set for the specified descriptor, returning the appropriate {@link LookupResult}.
     * Used for URL-based lists like URLhaus that need to check the full URL path, not just the hostname.
     *
     * @param descriptor The list descriptor to lookup against.
     * @param url The full URL to lookup for listing (e.g., "raw.githubusercontent.com/path/to/file").
     * @return The {@link LookupResult} for this URL: either the descriptor's configured result type if listed,
     *         or {@link LookupResult#ALLOWED} if not listed or if the list has not yet been loaded (fail-open).
     */
    public static @NonNull LookupResult lookupUrl(@NonNull Descriptor descriptor, @NonNull String url) {
        AtomicReference<ListSnapshot> ref = stateMap.get(descriptor);

        if (ref == null) {
            return LookupResult.FAILED;
        }

        Set<String> urlSet = ref.get().domainSet();

        if (urlSet == null) {
            log.warn("[{}] List not yet loaded; skipping pending lookup", descriptor.getShortName());
            return LookupResult.FAILED;
        }
        return isUrlInSet(urlSet, url) ? descriptor.getResultType() : LookupResult.ALLOWED;
    }

    /**
     * Checks whether the given hostname or any of its ancestor domains (up to but not including
     * the TLD) appears in the given domain set.
     *
     * @param domainSet The set of normalized hostnames to check against.
     * @param host The raw hostname to check.
     * @return {@code true} if the host or any ancestor domain is in the set.
     */
    private static boolean isHostInSet(@NonNull Collection<String> domainSet, @NonNull String host) {
        String normalized = host.strip().toLowerCase(Locale.ROOT);

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
     * Checks whether the given URL (or any parent path of it) appears in the given URL set.
     * This is used for URL-based lists that contain full paths.
     * Performs exact matching and also checks progressively shorter paths.
     * For example, when checking "raw.githubusercontent.com/owner/repo/file.exe", it will also check
     * "raw.githubusercontent.com/owner/repo" and "raw.githubusercontent.com/owner".
     *
     * @param urlSet The set of normalized URLs/paths to check against.
     * @param url The raw URL to check (e.g., "raw.githubusercontent.com/path/to/file").
     * @return {@code true} if the URL or any parent path is in the set.
     */
    private static boolean isUrlInSet(@NonNull Collection<String> urlSet, @NonNull String url) {
        String normalized = normalizeUrlForLookup(url);

        if (normalized == null) {
            return false;
        }

        if (urlSet.contains(normalized)) {
            return true;
        }

        // Check progressively shorter paths by removing trailing path segments
        int lastSlash = normalized.lastIndexOf('/');
        while (lastSlash > 0) {
            String parentPath = normalized.substring(0, lastSlash);

            if (urlSet.contains(parentPath)) {
                return true;
            }

            lastSlash = parentPath.lastIndexOf('/');
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
            AtomicReference<ListSnapshot> state = stateMap.get(descriptor);

            // Checks if the state slot is null, which should never happen
            if (state == null) {
                log.warn("[{}] No state slot exists for descriptor", descriptor.getShortName());
                return;
            }

            ListSnapshot current = state.get();
            FetchResult result = fetchRaw(descriptor, current.etag());

            // If result is null, the server returned 304 Not Modified, so we can skip
            // the update and keep the current snapshot
            if (result != null) {
                applyContent(descriptor, result.domainSet(), result.etag());
            }
        } catch (IOException | RuntimeException e) {
            log.warn("[{}] Failed to fetch list update: {} ({})",
                    descriptor.getShortName(), e.getMessage(), e.getClass().getName());
        }
    }

    /**
     * Fetches and parses content from the descriptor's URL.
     * <p>
     * If {@code currentEtag} is non-null, it is sent as {@code If-None-Match}. A 304 Not Modified
     * response causes this method to return {@code null}, signaling that the caller should skip
     * the update. A 200 response is parsed directly from the response stream with hard byte and
     * domain-count caps; the raw body is never materialized as one byte array or string.
     *
     * @param descriptor The list descriptor to fetch.
     * @param currentEtag The ETag from the last successful fetch, or {@code null} on first fetch.
     * @return A {@link FetchResult} with the parsed domains and ETag, or {@code null} on 304.
     */
    @SuppressWarnings("NestedMethodCall")
    private static @Nullable FetchResult fetchRaw(@NonNull Descriptor descriptor,
                                                  @Nullable String currentEtag) throws IOException {
        ClassicHttpRequest request = new HttpGet(descriptor.getUrl());
        request.addHeader("Accept", "application/json, text/plain, */*");

        if (currentEtag != null) {
            request.addHeader("If-None-Match", currentEtag);
        }

        return FETCH_CLIENT.execute(request, response -> {
            int statusCode = response.getCode();

            if (statusCode == 304) {
                EntityUtils.consumeQuietly(response.getEntity());
                return null;
            }

            if (statusCode != 200) {
                EntityUtils.consumeQuietly(response.getEntity());
                throw new IllegalStateException("HTTP " + statusCode);
            }

            String contentType = Optional.ofNullable(response.getFirstHeader("Content-Type"))
                    .map(Header::getValue)
                    .orElse("")
                    .toLowerCase(Locale.ROOT);

            if (!contentType.contains("application/json") && !contentType.contains("text/")) {
                EntityUtils.consumeQuietly(response.getEntity());
                throw new IllegalStateException("Unexpected Content-Type: " + contentType);
            }

            HttpEntity entity = response.getEntity();

            // Checks if the entity is null, which should not happen with a 200 response
            if (entity == null) {
                throw new IllegalStateException("Response body was empty");
            }

            Set<String> domains;

            // Parses directly from the response stream with caps to prevent OOM or DoS from large lists
            try (InputStream body = entity.getContent()) {
                domains = descriptor.getFormat() == Format.TEXT
                        ? parsePlainText(body, descriptor.isUrlBased())
                        : parseJson(body, descriptor.isUrlBased());
            } catch (IOException | RuntimeException e) {
                EntityUtils.consumeQuietly(entity);
                throw e;
            }

            // Checks if the parsed list is empty
            if (domains.isEmpty()) {
                throw new IllegalStateException("Parsed list was empty");
            }

            String etag = Optional.ofNullable(response.getFirstHeader("ETag"))
                    .map(Header::getValue)
                    .orElse(null);
            return new FetchResult(domains, etag);
        });
    }

    /**
     * Applies a parsed domain set to the live snapshot for the given descriptor.
     *
     * @param descriptor The list descriptor to update.
     * @param domainSet The parsed domain set.
     * @param etag The ETag from the response, or {@code null} if the server did not send one.
     */
    private static void applyContent(@NonNull Descriptor descriptor,
                                     @NonNull Set<String> domainSet,
                                     @Nullable String etag) {
        if (domainSet.isEmpty()) {
            log.warn("[{}] Refusing to apply empty parsed list; keeping current snapshot",
                    descriptor.getShortName());
            return;
        }

        AtomicReference<ListSnapshot> state = stateMap.get(descriptor);

        if (state == null) {
            log.warn("[{}] No state slot exists for descriptor", descriptor.getShortName());
            return;
        }

        state.set(new ListSnapshot(Collections.unmodifiableSet(domainSet), etag));
    }

    /**
     * Parses JSON content into a set of hostnames or URLs.
     * Expects a JSON array of strings. Null entries and empty strings are ignored.
     *
     * @param rawJson The raw JSON stream from the list endpoint.
     * @param isUrlBased Whether to parse as full URLs (true) or just hostnames (false).
     * @return A set of hostnames or URLs.
     */
    @SuppressWarnings({"NestedMethodCall", "NestedAssignment"})
    private static @NonNull Set<String> parseJson(@NonNull InputStream rawJson, boolean isUrlBased) {
        Set<String> set = new HashSet<>();

        try (JsonParser parser = JacksonUtil.MAPPER.createParser(cappedInputStream(rawJson))) {
            JsonToken token = parser.nextToken();

            if (token != JsonToken.START_ARRAY) {
                throw new IllegalArgumentException("Expected a JSON array");
            }

            while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
                if (token == null) {
                    throw new IllegalArgumentException("Unexpected end of JSON array");
                }

                if (token == JsonToken.VALUE_NULL) {
                    continue;
                }

                if (token != JsonToken.VALUE_STRING) {
                    throw new IllegalArgumentException("Expected JSON string entry but got " + token);
                }

                addNormalizedEntry(parser.getString(), set, isUrlBased);
            }
        }
        return set;
    }

    /**
     * Parses plain text content into a set of hostnames or URLs.
     * Lines starting with '#' and blank lines are ignored as comments.
     * Hosts-file format lines are supported.
     *
     * @param rawText The raw text stream from the list endpoint.
     * @param isUrlBased Whether to parse as full URLs (true) or just hostnames (false).
     * @return A set of hostnames or URLs.
     */
    @SuppressWarnings("NestedAssignment")
    private static @NonNull Set<String> parsePlainText(@NonNull InputStream rawText, boolean isUrlBased) throws IOException {
        Set<String> set = new HashSet<>();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(cappedInputStream(rawText), StandardCharsets.UTF_8))) {
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.length() > MAX_LINE_CHARS) {
                    throw new IllegalArgumentException("List line exceeds " + MAX_LINE_CHARS + " characters");
                }

                addNormalizedEntry(line, set, isUrlBased);
            }
        }
        return set;
    }

    /**
     * Normalizes and adds one list entry to the destination set.
     *
     * @param rawEntry The raw list entry or line.
     * @param destination The destination set.
     * @param isUrlBased Whether to parse as full URLs (true) or just hostnames (false).
     */
    private static void addNormalizedEntry(@Nullable String rawEntry,
                                           @NonNull Collection<? super String> destination,
                                           boolean isUrlBased) {
        if (rawEntry == null) {
            return;
        }

        String normalized = normalizeListEntry(rawEntry, isUrlBased);

        if (normalized == null) {
            return;
        }

        if (!destination.contains(normalized) && destination.size() >= MAX_DOMAINS) {
            throw new IllegalStateException("List exceeds " + MAX_DOMAINS + " unique domains");
        }

        destination.add(normalized);
    }

    /**
     * Normalizes a URL for lookup purposes, stripping protocol, www prefix, and trailing slashes,
     * but keeping the path portion.
     * Examples:
     * - "https://www.example.com/path/file" -> "example.com/path/file"
     * - "http://example.com/path/" -> "example.com/path"
     *
     * @param url The raw URL string.
     * @return The normalized URL/path, or {@code null} if the URL is invalid.
     */
    private static @Nullable String normalizeUrlForLookup(@NonNull String url) {
        String normalized = url.strip().toLowerCase(Locale.ROOT);

        if (normalized.isEmpty()) {
            return null;
        }

        // Strip protocol
        if (normalized.startsWith("https://")) {
            normalized = normalized.substring(8);
        } else if (normalized.startsWith("http://")) {
            normalized = normalized.substring(7);
        }

        // Strip www. prefix
        if (normalized.startsWith("www.")) {
            normalized = normalized.substring(4);
        }

        // Strip trailing slashes
        while (!normalized.isEmpty() && normalized.charAt(normalized.length() - 1) == '/') {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        if (normalized.isEmpty() || normalized.contains(" ") || normalized.contains("\\")) {
            return null;
        }
        return normalized;
    }

    /**
     * Normalizes one plain list entry, URL, or hosts-file line.
     *
     * @param rawEntry The raw entry.
     * @param isUrlBased Whether this list is URL-based (keeps path) or hostname-based (extracts hostname only).
     * @return The normalized domain or URL, or {@code null} if the entry should be ignored.
     */
    private static @Nullable String normalizeListEntry(@NonNull String rawEntry, boolean isUrlBased) {
        String entry = rawEntry.strip();

        if (entry.isEmpty() || entry.charAt(0) == '#') {
            return null;
        }

        int commentIndex = entry.indexOf('#');

        if (commentIndex >= 0) {
            entry = entry.substring(0, commentIndex).strip();
        }

        if (entry.isEmpty()) {
            return null;
        }

        int whitespaceIndex = firstWhitespaceIndex(entry);

        if (whitespaceIndex >= 0) {
            String first = entry.substring(0, whitespaceIndex);
            String remainder = entry.substring(whitespaceIndex).strip();

            if (looksLikeHostsFileAddress(first) && !remainder.isEmpty()) {
                int nextWhitespace = firstWhitespaceIndex(remainder);
                entry = nextWhitespace >= 0 ? remainder.substring(0, nextWhitespace) : remainder;
            } else {
                entry = first;
            }
        }

        // For URL-based lists, normalize the full URL; for hostname-based lists, extract just the hostname
        if (isUrlBased) {
            return normalizeUrlForLookup(entry);
        } else {
            entry = extractHostnameIfUrl(entry);

            if (entry == null) {
                return null;
            }

            String normalized = entry.strip().toLowerCase(Locale.ROOT);

            while (!normalized.isEmpty() && normalized.charAt(0) == '.') {
                normalized = normalized.substring(1);
            }

            while (!normalized.isEmpty() && normalized.charAt(normalized.length() - 1) == '.') {
                normalized = normalized.substring(0, normalized.length() - 1);
            }

            if (normalized.startsWith("www.")) {
                normalized = normalized.substring(4);
            }

            if (!normalized.contains(".")
                    || normalized.length() > MAX_DOMAIN_CHARS
                    || normalized.contains(" ")
                    || normalized.contains("/")
                    || normalized.contains("\\")) {
                return null;
            }
            return normalized;
        }
    }

    /**
     * Extracts the host component from a URL, or returns the input unchanged if it is not a URL.
     *
     * @param entry The candidate entry.
     * @return The host component for URLs, the original entry for non-URLs, or {@code null} if the URL is invalid.
     */
    private static @Nullable String extractHostnameIfUrl(@NonNull String entry) {
        if (!entry.contains("://")) {
            return entry;
        }

        try {
            String host = URI.create(entry).getHost();
            return host == null || host.isBlank() ? null : host;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Finds the first whitespace character in a string.
     *
     * @param value The value to inspect.
     * @return The first whitespace index, or -1 if none exists.
     */
    private static int firstWhitespaceIndex(@NonNull CharSequence value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isWhitespace(value.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Checks whether a token looks like the address column in a hosts-file line.
     *
     * @param value The token to inspect.
     * @return {@code true} if the token looks like an IP address placeholder.
     */
    private static boolean looksLikeHostsFileAddress(@NonNull String value) {
        if ("localhost".equalsIgnoreCase(value) || value.indexOf(':') >= 0) {
            return true;
        }

        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }

            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);

                if (c < '0' || c > '9') {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Wraps an input stream and fails once more than MAX_LIST_BYTES are read.
     *
     * @param delegate The stream to wrap.
     * @return A capped stream.
     */
    @Contract(value = "_ -> new", pure = true)
    private static @NonNull InputStream cappedInputStream(@NonNull InputStream delegate) {
        return new FilterInputStream(delegate) {
            private long bytesRead;

            @Override
            public int read() throws IOException {
                int value = super.read();

                if (value != -1) {
                    countBytes(1);
                }
                return value;
            }

            @Override
            public int read(byte @NonNull [] b, int off, int len) throws IOException {
                int count = super.read(b, off, len);
                countBytes(count);
                return count;
            }

            @Contract(mutates = "this")
            private void countBytes(int count) throws IOException {
                if (count <= 0) {
                    return;
                }

                bytesRead += count;

                if (bytesRead > MAX_LIST_BYTES) {
                    throw new IOException("List exceeds " + MAX_LIST_BYTES + " bytes");
                }
            }
        };
    }
}
