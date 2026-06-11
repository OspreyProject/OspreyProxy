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

import com.google.common.net.InternetDomainName;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.util.HttpClientFactory;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
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

    // Minimum number of comma-separated fields required in a CSV threat-feed line
    private static final int MIN_CSV_FIELDS = 4;

    // Constants for parsing limits to prevent OOM or DoS from unexpectedly large lists
    private static final int MAX_LIST_BYTES = 16 * 1024 * 1024;
    private static final int MAX_DOMAINS = 1_000_000;
    private static final int MAX_LINE_CHARS = 10_248;
    private static final int MAX_DOMAIN_CHARS = 253;

    // Runtime state per descriptor, keyed by descriptor identity
    private static final Map<Descriptor, AtomicReference<ListSnapshot>> stateMap = new EnumMap<>(Descriptor.class);

    // Descriptors keyed by endpoint name for O(1) routing in ProxyHandler
    private static final Map<String, Descriptor> descriptorsByEndpointName;

    // Scheduler for periodic list refreshes
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor((Runnable r) -> {
        Thread thread = new Thread(r, "local-list-refresh");
        thread.setDaemon(true);
        return thread;
    });

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

            // If this descriptor requires an API key that isn't configured, skip scheduling
            // and leave the state slot at EMPTY (fail-open for lookups).
            if (descriptor.getResolvedUrl() == null) {
                log.warn("[{}] Skipping list feed: {} environment variable is not set",
                        descriptor.getShortName(), descriptor.getApiKeyEnvVar());
                continue;
            }

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
     * Looks up the given request URI against the live set for the specified descriptor.
     *
     * @param descriptor The list descriptor to look up against.
     * @param fullUri The full request URI including scheme (e.g. {@code https://example.com/path}).
     * @return The {@link LookupResult} for this URI: the descriptor's result type if listed,
     *         {@link LookupResult#ALLOWED} if not listed, or {@link LookupResult#FAILED}
     *         if the list has not yet been loaded.
     */
    public static @NonNull LookupResult lookup(@NonNull Descriptor descriptor, @NonNull String fullUri) {
        AtomicReference<ListSnapshot> ref = stateMap.get(descriptor);

        if (ref == null) {
            return LookupResult.FAILED;
        }

        Set<String> domainSet = ref.get().domainSet();

        if (domainSet == null) {
            log.warn("[{}] List not yet loaded; skipping pending lookup", descriptor.getShortName());
            return LookupResult.FAILED;
        }

        URI uri;

        try {
            uri = URI.create(fullUri);
        } catch (IllegalArgumentException ignored) {
            return LookupResult.ALLOWED;
        }

        String host = uri.getHost();

        if (host == null || host.isBlank()) {
            return LookupResult.ALLOWED;
        }

        host = host.toLowerCase(Locale.ROOT);

        if (host.startsWith("www.")) {
            host = host.substring(4);
        }

        if (isHostInSet(domainSet, host)) {
            return descriptor.getResultType();
        }

        String rawPath = uri.getRawPath();
        boolean hasPath = rawPath != null && !rawPath.isEmpty() && !"/".equals(rawPath);

        if (hasPath) {
            String path = rawPath.toLowerCase(Locale.ROOT);

            while (!path.isEmpty() && path.charAt(path.length() - 1) == '/') {
                path = path.substring(0, path.length() - 1);
            }

            if (isUrlInSet(domainSet, host + path)) {
                return descriptor.getResultType();
            }
        }
        return LookupResult.ALLOWED;
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

        // Walk ancestors, but never below the registrable domain
        int minLabels = 2;
        try {
            InternetDomainName idn = InternetDomainName.from(normalized);

            if (idn.hasPublicSuffix() && idn.publicSuffix() != null) {
                minLabels = idn.publicSuffix().parts().size() + 1;
            }
        } catch (IllegalArgumentException ignored) {
            // ignored
        }

        String[] labels = normalized.split("\\.", -1);

        for (int i = 1; i <= labels.length - minLabels; i++) {
            String ancestor = String.join(".", Arrays.copyOfRange(labels, i, labels.length));

            if (domainSet.contains(ancestor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the given URL path (or any parent path of it) appears in the given URL set.
     *
     * @param urlSet The set of normalized URL paths to check against.
     * @param urlPath The scheme-stripped, normalized URL path to check (e.g. {@code "host/path"}).
     * @return {@code true} if the URL path or any parent path is in the set.
     */
    private static boolean isUrlInSet(@NonNull Collection<String> urlSet, @NonNull String urlPath) {
        String normalized = normalizeUrlForLookup(urlPath);

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
            log.warn("[{}] Failed to fetch list update: {}", descriptor.getShortName(), e.getClass().getName());
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
        ClassicHttpRequest request = new HttpGet(descriptor.getResolvedUrl());
        request.addHeader("Accept", "application/json, text/plain, */*");

        if (currentEtag != null) {
            request.addHeader("If-None-Match", currentEtag);
        }

        return FETCH_CLIENT.execute(request, (ClassicHttpResponse response) -> {
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
                domains = switch (descriptor.getFormat()) {
                    case TEXT -> parsePlainText(body);
                    case CSV -> parseCsv(body);
                    case JSON -> parseJson(body);
                };
            } catch (IOException | RuntimeException e) {
                EntityUtils.consumeQuietly(entity);
                throw new IOException("Failed to parse list content: " + e.getMessage(), e);
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
     * Parses JSON content into a set of hostnames and URL paths.
     * Expects a JSON array of strings. Null entries and empty strings are ignored.
     *
     * @param rawJson The raw JSON stream from the list endpoint.
     * @return A set of normalized hostnames and URL paths.
     */
    @SuppressWarnings({"NestedMethodCall", "NestedAssignment"})
    private static @NonNull Set<String> parseJson(@NonNull InputStream rawJson) {
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

                addNormalizedEntry(parser.getString(), set);
            }
        }
        return set;
    }

    /**
     * Parses a comma-separated threat-feed into a set of hostnames and URL paths.
     * Expects lines with at least four fields: timestamp, source, type, indicator.
     * Lines starting with {@code #} and blank lines are ignored.
     *
     * @param rawCsv The raw CSV stream from the list endpoint.
     * @return A set of normalized hostnames and URL paths.
     */
    @SuppressWarnings("NestedAssignment")
    private static @NonNull Set<String> parseCsv(@NonNull InputStream rawCsv) throws IOException {
        Set<String> set = new HashSet<>();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(cappedInputStream(rawCsv), StandardCharsets.UTF_8))) {
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.length() > MAX_LINE_CHARS) {
                    throw new IllegalArgumentException("List line exceeds " + MAX_LINE_CHARS + " characters");
                }

                String stripped = line.strip();

                if (stripped.isEmpty() || stripped.charAt(0) == '#') {
                    continue;
                }

                // Split on every comma so that optional trailing fields (tags, reference)
                // do not affect the position of the indicator at index 3
                String[] fields = stripped.split(",", -1);

                if (fields.length < MIN_CSV_FIELDS) {
                    continue;
                }

                addNormalizedEntry(fields[3].strip(), set);
            }
        }
        return set;
    }

    /**
     * Parses plain text content into a set of hostnames and URL paths.
     * Lines starting with {@code #} and blank lines are ignored.
     * Hosts-file format lines are supported.
     *
     * @param rawText The raw text stream from the list endpoint.
     * @return A set of normalized hostnames and URL paths.
     */
    @SuppressWarnings("NestedAssignment")
    private static @NonNull Set<String> parsePlainText(@NonNull InputStream rawText) throws IOException {
        Set<String> set = new HashSet<>();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(cappedInputStream(rawText), StandardCharsets.UTF_8))) {
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.length() > MAX_LINE_CHARS) {
                    throw new IllegalArgumentException("List line exceeds " + MAX_LINE_CHARS + " characters");
                }

                addNormalizedEntry(line, set);
            }
        }
        return set;
    }

    /**
     * Normalizes and adds one list entry to the destination set.
     *
     * @param rawEntry The raw list entry or line.
     * @param destination The destination set.
     */
    private static void addNormalizedEntry(@Nullable String rawEntry,
                                           @NonNull Collection<? super String> destination) {
        if (rawEntry == null) {
            return;
        }

        String normalized = normalizeListEntry(rawEntry);

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
     * @return The normalized hostname or URL path, or {@code null} if the entry should be ignored.
     */
    private static @Nullable String normalizeListEntry(@NonNull String rawEntry) {
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
        return entry.contains("://") ? normalizeUrlEntry(entry) : normalizeHostnameEntry(entry);
    }

    /**
     * Normalizes a URL entry, storing it either as a bare hostname or as {@code host/path}
     * depending on whether the URL carries a meaningful path.
     *
     * @param entry The URL entry string (must contain {@code ://}).
     * @return The normalized hostname or URL path, or {@code null} if the entry is invalid.
     */
    private static @Nullable String normalizeUrlEntry(@NonNull String entry) {
        URI uri;

        try {
            uri = URI.create(entry);
        } catch (IllegalArgumentException e) {
            return null;
        }

        String host = uri.getHost();

        if (host == null || host.isBlank()) {
            return null;
        }

        host = host.toLowerCase(Locale.ROOT);

        if (host.startsWith("www.")) {
            host = host.substring(4);
        }

        String rawPath = uri.getRawPath();
        boolean hasPath = rawPath != null && !rawPath.isEmpty() && !"/".equals(rawPath);

        if (!hasPath) {
            return normalizeHostnameEntry(host);
        }

        String path = rawPath.toLowerCase(Locale.ROOT);

        while (!path.isEmpty() && path.charAt(path.length() - 1) == '/') {
            path = path.substring(0, path.length() - 1);
        }

        String result = host + path;
        return result.contains(" ") || result.contains("\\") ? null : result;
    }

    /**
     * Normalizes a bare hostname entry, lowercasing it, stripping leading/trailing dots
     * and the {@code www.} prefix, and validating that the result is a usable hostname.
     *
     * @param entry The raw hostname string (must not contain {@code ://}).
     * @return The normalized hostname, or {@code null} if the entry is invalid.
     */
    private static @Nullable String normalizeHostnameEntry(@NonNull String entry) {
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

        // Refuse entries that are registry suffixes, since they would cause every possible
        // subdomain to match and are unlikely to be intentional list entries
        try {
            if (InternetDomainName.from(normalized).isRegistrySuffix()) {
                log.warn("Refusing list entry that is a registry suffix: {}", normalized);
                return null;
            }
        } catch (IllegalArgumentException ignored) {
            // ignored
        }
        return normalized;
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
     * Accepts "localhost", IPv6 addresses (containing ':'), and dotted-decimal IPv4
     * addresses whose four octets are each a valid decimal integer in [0, 255] with
     * no leading zeros (except the bare value "0").
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

            if (part.length() > 1 && part.charAt(0) == '0') {
                return false;
            }

            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);

                if (c < '0' || c > '9') {
                    return false;
                }
            }

            if (Integer.parseInt(part) > 255) {
                return false;
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
