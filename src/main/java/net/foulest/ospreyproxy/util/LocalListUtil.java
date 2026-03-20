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
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
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
 * Utility class for managing local lists of domains fetched from external sources.
 */
@Slf4j
@Component
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LocalListUtil {

    // HTTP/2 client for list fetches
    // Multiplexing handles max conn. total and max conn. per route
    // 30s connect timeout, 30s connection request timeout, 30s response timeout, 35s operation timeout
    private static final CloseableHttpClient FETCH_CLIENT;

    static {
        CloseableHttpAsyncClient asyncClient = HttpAsyncClients.customHttp2()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(30))
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                        .setResponseTimeout(Timeout.ofSeconds(30))
                        .build())
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .build();

        asyncClient.start();
        FETCH_CLIENT = HttpAsyncClients.classic(asyncClient, Timeout.ofSeconds(35));
    }

    // How often to re-fetch each list
    private static final long UPDATE_INTERVAL_SECONDS = 5 * 60L;

    // Scheduler for periodic list refreshes
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "local-list-refresh");
        thread.setDaemon(true);
        return thread;
    });

    // Runtime state per descriptor, keyed by descriptor identity
    private static final Map<Descriptor, AtomicReference<State>> stateMap = new EnumMap<>(Descriptor.class);

    /**
     * Enumeration of supported list descriptors, each with its URL, content format, and short name for logging.
     * The content format determines how the raw response is parsed into a set of hostnames.
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

    /**
     * List content format.
     */
    private enum Format {
        JSON,
        TEXT
    }

    /**
     * Runtime state for a single descriptor, including the live set of
     * domains and the raw content string from the last successful fetch.
     */
    private static final class State {

        /**
         * The live set of domains for this descriptor, or null if the list has not yet been loaded.
         */
        volatile @Nullable Set<String> domainSet;

        /**
         * The raw content string from the last successful fetch.
         * Used to detect changes and avoid unnecessary rebuilds.
         */
        volatile @Nullable String rawContent;

        State() {
            domainSet = null;
            rawContent = null;
        }
    }

    @PostConstruct
    public void init() {
        for (Descriptor descriptor : Descriptor.values()) {
            stateMap.put(descriptor, new AtomicReference<>(new State()));
        }

        for (Descriptor descriptor : Descriptor.values()) {
            // Immediate fetch on startup, then repeat every 5 minutes
            scheduler.scheduleWithFixedDelay(
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

    /**
     * Checks if the given host is listed in the live set for the specified descriptor.
     * If the list has not yet been loaded, this method returns {@code false} (fail-open).
     * <p>
     * The check is case-insensitive and ignores leading/trailing whitespace.
     * It also implements subdomain walk-up: a hostname is considered listed if the hostname itself,
     * or any ancestor domain up to (but not including) the TLD, appears in the set.
     *
     * @param descriptor The list descriptor to check against.
     * @param host The hostname to check for listing.
     * @return {@code true} if the host is listed, {@code false} if it is not listed or if the list has not yet been loaded.
     */
    public static boolean isListed(@NonNull Descriptor descriptor, @NonNull String host) {
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
        for (int i = 1; i < labels.length - 1; i++) {
            String ancestor = String.join(".", Arrays.copyOfRange(labels, i, labels.length));

            if (domainSet.contains(ancestor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the number of domains currently in the given descriptor's live set.
     *
     * @param descriptor The list descriptor to check.
     * @return The number of domains in the live set, or 0 if the list has not yet been loaded.
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
     * Fetches the list content from the descriptor's URL and updates the live domain set.
     * If the content is unchanged from the last successful fetch, the update is skipped.
     *
     * @param descriptor The list descriptor to fetch and update.
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
     * Fetches the raw content string from the descriptor's URL.
     * Validates that the response has a 200 status code and an expected content type.
     * Enforces a maximum response size of 50 MiB to prevent OOM errors.
     *
     * @param descriptor The list descriptor to fetch.
     * @return The raw content string from the response.
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
            byte[] body = EntityUtils.toByteArray(entity, 50 * 1024 * 1024);

            if (body == null || body.length == 0) {
                throw new IllegalStateException("Response body was empty");
            }
            return new String(body, StandardCharsets.UTF_8);
        });
    }

    /**
     * Parses the raw content and updates the live domain set for the given descriptor.
     * If the content is unchanged from the last successful fetch, the update is skipped.
     *
     * @param descriptor The list descriptor to update.
     * @param rawContent The raw content string to parse and apply.
     */
    private static void applyContent(@NonNull Descriptor descriptor, @NonNull String rawContent) {
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
     * Parses JSON content into a set of hostnames.
     * Expects a JSON array of strings. Null entries and empty strings are ignored.
     * Leading/trailing whitespace is trimmed, and all entries are normalized to lower-case.
     *
     * @param rawJson The raw JSON content from the list endpoint.
     * @return A set of hostnames.
     */
    private static @NonNull Set<String> parseJson(@NonNull String rawJson) {
        List<String> parsed = JacksonUtil.MAPPER.readValue(rawJson, JacksonUtil.LIST_TYPE);

        // Checks if the parsed list is null
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

            // Strip leading www. and normalize to lower-case (mirrors the extension)
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
