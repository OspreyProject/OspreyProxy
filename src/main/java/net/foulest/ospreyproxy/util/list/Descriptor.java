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

import lombok.Getter;
import net.foulest.ospreyproxy.result.LookupResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a descriptor for a list provider, containing all necessary information to fetch and interpret the list.
 * <p>
 * A descriptor may aggregate more than one source URL under a single endpoint. When multiple URLs
 * are present, each is fetched and conditionally refreshed independently (its own ETag), and the
 * parsed domains from every source are merged into one live set served by the descriptor's endpoint.
 */
@Getter
public enum Descriptor {

    /**
     * Artists Against 419 (AA419)
     */
    AA419(
            List.of("https://api.aa419.org/fakesites?fields=Url&pgsize=500&expired=0"),
            Format.JSON,
            "AA419",
            "aa419",
            LookupResult.MALICIOUS,
            300L,
            "AA419_API_KEY",
            true,
            "Auth-API-Id",
            "Url"
    ),

    /**
     * OpenPhish
     */
    OPEN_PHISH(
            List.of("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"),
            Format.TEXT,
            "OpenPhish",
            "openphish",
            LookupResult.PHISHING,
            300L,
            null
    ),

    /**
     * PhishDestroy
     */
    PHISH_DESTROY(
            List.of("https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt"),
            Format.TEXT,
            "PhishDestroy",
            "phishdestroy",
            LookupResult.PHISHING,
            300L,
            null
    ),

    /**
     * Phishunt.io
     */
    PHISHUNT_IO(
            List.of("https://phishunt.io/feed.txt"),
            Format.TEXT,
            "Phishunt.io",
            "phishunt-io",
            LookupResult.PHISHING,
            300L,
            null
    ),

    /**
     * Red Flag Domains
     */
    RED_FLAG_DOMAINS(
            List.of("https://dl.red.flag.domains/red.flag.domains.txt"),
            Format.TEXT,
            "Red Flag Domains",
            "red-flag-domains",
            LookupResult.MALICIOUS,
            300L,
            null
    ),

    /**
     * SecureFeed
     */
    SECURE_FEED(
            List.of("https://api.securefeed.com/Host/Feed?dateRange=5&type=host&tag=all&apiKey=%api_key%"),
            Format.TEXT,
            "SecureFeed",
            "securefeed",
            LookupResult.MALICIOUS,
            600L, // keep at 600L
            "SECUREFEED_API_KEY"
    ),

    /**
     * SinkingYachts
     */
    SINKING_YACHTS(
            List.of("https://phish.sinking.yachts/v2/text"),
            Format.TEXT,
            "SinkingYachts",
            "sinking-yachts",
            LookupResult.PHISHING,
            300L,
            null
    ),

    /**
     * THREATfox
     */
    THREATFOX(
            List.of("https://threatfox-api.abuse.ch/v2/files/exports/%api_key%/hostfile.txt"),
            Format.TEXT,
            "THREATfox",
            "threatfox",
            LookupResult.MALICIOUS,
            300L,
            "THREATFOX_API_KEY"
    ),

    /**
     * URLhaus
     */
    URLHAUS(
            List.of("https://urlhaus.abuse.ch/downloads/text"),
            Format.TEXT,
            "URLhaus",
            "urlhaus",
            LookupResult.MALICIOUS,
            300L,
            null
    ),

    /**
     * Validin
     */
    VALIDIN(
            List.of(
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-1.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-2.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-3.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-4.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-5.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-6.txt",
                    "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/main/validin-phish-feed-7.txt"
            ),
            Format.TEXT,
            "Validin",
            "validin",
            LookupResult.PHISHING,
            600L, // keep at 600L
            null
    );

    /**
     * The URL templates from which to fetch the list data.
     * Each entry may contain {@code %api_key%} as a placeholder, which is substituted at runtime
     * with the value of the environment variable named by {@link #apiKeyEnvVar}.
     * Most descriptors have a single source; some aggregate several into one endpoint.
     */
    private final List<String> urls;

    /**
     * The format of the list, which determines how it should be parsed.
     */
    private final Format format;

    /**
     * A human-readable name for this list, used in logging.
     */
    private final String shortName;

    /**
     * The endpoint name for this list, used in configuration and routing.
     */
    private final String endpointName;

    /**
     * The type of result to return when a domain is found in this list.
     */
    private final LookupResult resultType;

    /**
     * The interval in seconds at which this list should be refreshed.
     */
    private final long refreshIntervalSeconds;

    /**
     * The name of the environment variable that holds the API key for this feed,
     * or {@code null} if no key is required.
     * When non-null, {@link #getResolvedUrls()} substitutes {@code %api_key%} in each
     * URL with the value of this environment variable. If {@link #authHeaderName} is also
     * set, the same environment variable's value is instead (or additionally) sent as an
     * authentication request header.
     */
    private final @Nullable String apiKeyEnvVar;

    /**
     * Whether this descriptor accumulates domains across fetches instead of overwriting.
     * <p>
     * When {@code false} (the default) each refresh republishes only what the current fetch
     * returned, so a domain that disappears from the source is dropped. When {@code true},
     * every fetch unions its domains into the existing live set and nothing is ever removed;
     * the backing {@link java.util.Set} keeps the merged set de-duplicated. This suits feeds
     * that expose only a rolling window of recent entries (e.g. AA419).
     */
    private final boolean accumulate;

    /**
     * The name of an HTTP request header used to authenticate the fetch (e.g. {@code Auth-API-Id}),
     * or {@code null} if the feed needs no auth header. When non-null, the header is sent on every
     * fetch with the value of the {@link #apiKeyEnvVar} environment variable.
     */
    private final @Nullable String authHeaderName;

    /**
     * For {@link Format#JSON} feeds that return an array of objects, the name of the field on each
     * object that holds the URL or hostname (e.g. {@code Url}). When {@code null}, a JSON feed is
     * parsed as an array of bare strings (the original behavior).
     */
    private final @Nullable String jsonObjectField;

    /**
     * Canonical constructor.
     */
    Descriptor(@NonNull List<String> urls, @NonNull Format format, @NonNull String shortName,
               @NonNull String endpointName, @NonNull LookupResult resultType, long refreshIntervalSeconds,
               @Nullable String apiKeyEnvVar, boolean accumulate, @Nullable String authHeaderName,
               @Nullable String jsonObjectField) {
        this.urls = urls;
        this.format = format;
        this.shortName = shortName;
        this.endpointName = endpointName;
        this.resultType = resultType;
        this.refreshIntervalSeconds = refreshIntervalSeconds;
        this.apiKeyEnvVar = apiKeyEnvVar;
        this.accumulate = accumulate;
        this.authHeaderName = authHeaderName;
        this.jsonObjectField = jsonObjectField;
    }

    /**
     * Convenience constructor for the common case: overwrite semantics, no auth header, and
     * (for JSON) an array of bare strings. Existing descriptors use this seven-argument form.
     */
    Descriptor(@NonNull List<String> urls, @NonNull Format format, @NonNull String shortName,
               @NonNull String endpointName, @NonNull LookupResult resultType, long refreshIntervalSeconds,
               @Nullable String apiKeyEnvVar) {
        this(urls, format, shortName, endpointName, resultType, refreshIntervalSeconds, apiKeyEnvVar,
                false, null, null);
    }

    /**
     * Resolves the authentication header value from {@link #apiKeyEnvVar}, or returns {@code null}
     * if no auth header is configured or the environment variable is unset/blank.
     *
     * @return The header value to send, or {@code null} if none should be sent.
     */
    @Nullable String getAuthHeaderValue() {
        if (authHeaderName == null || apiKeyEnvVar == null) {
            return null;
        }

        String key = System.getenv(apiKeyEnvVar);
        return key == null || key.isBlank() ? null : key;
    }

    /**
     * Returns the fetch URLs with the {@code %api_key%} placeholder substituted in each.
     * <p>
     * If this descriptor requires an API key that is not configured, an empty list is returned
     * so the caller can skip scheduling entirely (fail-open for lookups).
     *
     * @return The resolved URLs, or an empty list if a required API key is not configured.
     */
    List<String> getResolvedUrls() {
        if (apiKeyEnvVar == null) {
            return urls;
        }

        String key = System.getenv(apiKeyEnvVar);

        if (key == null || key.isBlank()) {
            return List.of();
        }

        List<String> resolved = new ArrayList<>(urls.size());

        for (String url : urls) {
            resolved.add(url.replace("%api_key%", key));
        }
        return Collections.unmodifiableList(resolved);
    }
}
