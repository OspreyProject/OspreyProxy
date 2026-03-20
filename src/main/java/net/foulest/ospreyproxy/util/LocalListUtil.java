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
package net.foulest.ospreyproxy.util;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Fetches, persists in memory, and queries local phishing domain filtering lists.
 * <p>
 * Mirrors {@code LocalLists.js} from the Osprey browser extension.
 * On startup, immediately fetches each list and schedules a refresh every 5 minutes.
 * Lookups are available as soon as the first fetch completes; before that,
 * {@link #isListed(Descriptor, String)} returns {@code false} (fail-open).
 * <p>
 * Subdomain walk-up is implemented exactly as in the extension: a hostname is
 * considered listed if the hostname itself, or any ancestor domain up to (but not
 * including) the TLD, appears in the set.
 */
@Slf4j
@Component
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LocalListUtil {

    // How often to re-fetch each list (mirrors LocalLists.UPDATE_INTERVAL_MS = 5 minutes)
    private static final long UPDATE_INTERVAL_SECONDS = 5 * 60L;

    // Fetch timeout per list request (mirrors LocalLists.FETCH_TIMEOUT_MS = 30 seconds)
    private static final int FETCH_TIMEOUT_SECONDS = 30;

    // Jackson mapper for parsing JSON-format lists
    private static final ObjectMapper MAPPER = JsonMapper.builder().build();
    private static final JavaType LIST_TYPE = MAPPER.constructType(
            new TypeReference<List<String>>() {
            }
    );

    // Dedicated HTTP client for list fetches
    private static final CloseableHttpClient FETCH_CLIENT = HttpClients.custom()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setMaxConnTotal(10)
                    .setMaxConnPerRoute(5)
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(Timeout.ofSeconds(FETCH_TIMEOUT_SECONDS))
                            .build())
                    .build())
            .setDefaultRequestConfig(RequestConfig.custom()
                    .setConnectionRequestTimeout(Timeout.ofSeconds(FETCH_TIMEOUT_SECONDS))
                    .setResponseTimeout(Timeout.ofSeconds(FETCH_TIMEOUT_SECONDS))
                    .build())
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .build();

    // Scheduler for periodic list refreshes
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "local-list-refresh");
        t.setDaemon(true);
        return t;
    });

    // Runtime state per descriptor, keyed by descriptor identity
    private final Map<Descriptor, AtomicReference<State>> stateMap = new EnumMap<>(Descriptor.class);

    // -------------------------------------------------------------------------
    // Descriptor enum — mirrors LocalLists.descriptors in the extension
    // -------------------------------------------------------------------------

    /**
     * Describes a local filtering list, mirroring the descriptor objects in
     * {@code LocalLists.descriptors} from the browser extension.
     */
    @AllArgsConstructor
    public enum Descriptor {

        PHISH_DESTROY(
                "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json",
                Format.JSON,
                "PhishDestroy"
        ),

        PHISHING_DATABASE(
                "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt",
                Format.TEXT,
                "Phishing.Database"
        );

        final String url;
        final Format format;
        final String shortName;
    }

    /** List content format. */
    private enum Format {
        JSON, TEXT
    }

    // -------------------------------------------------------------------------
    // Runtime state holder
    // -------------------------------------------------------------------------

    /**
     * Holds the live domain set and the raw content string for a single descriptor.
     * Both fields are null until the first successful fetch.
     */
    private static final class State {

        /** The live domain set. {@code null} until the first successful fetch. */
        volatile @Nullable Set<String> domainSet;

        /** The raw content from the last successful fetch, used for change detection. */
        volatile @Nullable String rawContent;

        State() {
            domainSet = null;
            rawContent = null;
        }
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @PostConstruct
    public void init() {
        for (Descriptor descriptor : Descriptor.values()) {
            stateMap.put(descriptor, new AtomicReference<>(new State()));
        }

        for (Descriptor descriptor : Descriptor.values()) {
            // Immediate fetch on startup, then repeat every 5 minutes
            scheduler.scheduleAtFixedRate(
                    () -> fetchAndUpdate(descriptor),
                    0L,
                    UPDATE_INTERVAL_SECONDS,
                    TimeUnit.SECONDS
            );
        }
    }

    @PreDestroy
    public void destroy() {
        scheduler.shutdownNow();
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} if the given hostname (or any ancestor domain up to but
     * not including the TLD) appears in the given descriptor's domain set.
     * <p>
     * Mirrors the {@code isListed} check and subdomain walk-up logic in
     * {@code checkUrlWithLocalList} from {@code BrowserProtection.js}.
     * <p>
     * Returns {@code false} (fail-open) if the list has not yet been loaded.
     *
     * @param descriptor The list descriptor to check against.
     * @param host       The hostname to check, e.g. {@code "sub.example.com"}.
     * @return {@code true} if the host or any ancestor is listed.
     */
    public boolean isListed(@NonNull Descriptor descriptor, @NonNull String host) {
        AtomicReference<State> ref = stateMap.get(descriptor);

        if (ref == null) {
            return false;
        }

        Set<String> domainSet = ref.get().domainSet;

        if (domainSet == null) {
            log.warn("[{}] List not yet loaded; skipping check for '{}'", descriptor.shortName, host);
            return false;
        }

        String normalized = host.trim().toLowerCase(Locale.ROOT);

        // Check the hostname itself first
        if (domainSet.contains(normalized)) {
            return true;
        }

        String[] labels = normalized.split("\\.", -1);

        // Walk up the domain tree, checking each parent suffix.
        // Stops before the TLD (must have at least two labels to be meaningful).
        // Mirrors: for (let i = 1; i < labels.length - 1; i++) in the extension.
        for (int i = 1; i < labels.length - 1; i++) {
            String ancestor = String.join(".", Arrays.copyOfRange(labels, i, labels.length));

            if (domainSet.contains(ancestor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the number of entries currently loaded for the given descriptor.
     * Returns {@code 0} if the list has not yet been loaded.
     */
    public int size(@NonNull Descriptor descriptor) {
        AtomicReference<State> ref = stateMap.get(descriptor);

        if (ref == null) {
            return 0;
        }

        Set<String> domainSet = ref.get().domainSet;
        return domainSet != null ? domainSet.size() : 0;
    }

    /**
     * Fetches the latest raw content for the given descriptor and applies it.
     * Errors are caught and logged; they do not interrupt the update schedule.
     * <p>
     * Mirrors {@code LocalLists.fetchAndUpdate()} from the extension.
     */
    private void fetchAndUpdate(@NonNull Descriptor descriptor) {
        try {
            String rawContent = fetchRaw(descriptor);
            applyContent(descriptor, rawContent);
        } catch (Exception e) {
            log.warn("[{}] Failed to fetch list update: {} ({})", descriptor.shortName, e.getMessage(), e.getClass().getName());
        }
    }

    /**
     * Fetches the raw content string for the given descriptor.
     * <p>
     * Mirrors {@code LocalLists.fetchJson()} from the extension (handles both JSON and plain-text).
     *
     * @return The raw content string.
     * @throws Exception If the fetch fails (non-200, wrong content-type, empty body, I/O error).
     */
    private static @NonNull String fetchRaw(@NonNull Descriptor descriptor) throws Exception {
        HttpGet request = new HttpGet(descriptor.url);
        request.addHeader("Accept", "application/json, text/plain, */*");

        return FETCH_CLIENT.execute(request, response -> {
            int statusCode = response.getCode();

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
            byte[] body = EntityUtils.toByteArray(entity);

            if (body == null || body.length == 0) {
                throw new IllegalStateException("Response body was empty");
            }
            return new String(body, StandardCharsets.UTF_8);
        });
    }

    /**
     * Applies freshly fetched raw content to a descriptor's runtime state.
     * Compares against the currently loaded raw content and skips the rebuild if unchanged.
     * <p>
     * Mirrors {@code LocalLists.applyJson()} from the extension.
     *
     * @param descriptor The descriptor whose state to update.
     * @param rawContent The newly fetched raw content string.
     */
    private void applyContent(@NonNull Descriptor descriptor, @NonNull String rawContent) {
        AtomicReference<State> ref = stateMap.get(descriptor);
        State current = ref.get();

        // Skip rebuild if content is unchanged (mirrors the rawJson equality check in the extension)
        if (rawContent.equals(current.rawContent)) {
            return;
        }

        Set<String> newSet;
        try {
            newSet = descriptor.format == Format.TEXT
                    ? parsePlainText(rawContent)
                    : parseJson(rawContent);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to parse list; keeping current: {} ({})", descriptor.shortName, e.getMessage(), e.getClass().getName());
            return;
        }

        // Atomically swap in the new state
        State next = new State();
        next.domainSet = newSet;
        next.rawContent = rawContent;
        ref.set(next);
    }

    /**
     * Parses a JSON array of hostname strings into a set of lower-cased, trimmed hostnames.
     * Non-string and empty entries are silently ignored.
     * <p>
     * Mirrors {@code LocalLists.parseJson()} from the extension.
     *
     * @param rawJson The raw JSON text from the list endpoint.
     * @return A set of hostnames.
     */
    private static @NonNull Set<String> parseJson(@NonNull String rawJson) {
        List<String> parsed = MAPPER.readValue(rawJson, LIST_TYPE);

        // Checks if the parsed list is null
        if (parsed == null) {
            throw new IllegalArgumentException("Expected a JSON array but got null");
        }

        Set<String> set = new HashSet<>(parsed.size() * 2);

        for (String entry : parsed) {
            if (entry != null && !entry.isEmpty()) {
                set.add(entry.trim().toLowerCase(Locale.ROOT));
            }
        }
        return set;
    }

    /**
     * Parses a plain-text file (one hostname per line) into a set of lower-cased,
     * trimmed hostnames. Blank lines and lines beginning with {@code #} are ignored.
     * Hosts-file format ({@code 127.0.0.1\thostname.com}) is handled by taking the
     * tab-delimited second field.
     * <p>
     * Mirrors {@code LocalLists.parsePlainText()} from the extension.
     *
     * @param rawText The raw plain-text content from the list endpoint.
     * @return A set of hostnames.
     */
    private static @NonNull Set<String> parsePlainText(@NonNull String rawText) {
        Set<String> set = new HashSet<>();

        for (String line : rawText.split("\n", -1)) {
            String trimmed = line.trim();

            // Skip blank lines and comment lines
            if (trimmed.isEmpty() || trimmed.charAt(0) == '#') {
                continue;
            }

            // Handle hosts file format (e.g. "127.0.0.1\thostname.com")
            int tabIndex = trimmed.indexOf('\t');
            String entry = tabIndex == -1 ? trimmed : trimmed.substring(tabIndex + 1).trim();

            // Strip leading www. and normalize to lower-case (mirrors the extension)
            String normalized = entry.toLowerCase(Locale.ROOT);
            if (normalized.startsWith("www.")) {
                normalized = normalized.substring(4);
            }

            if (!normalized.isEmpty()) {
                set.add(normalized);
            }
        }
        return set;
    }
}
