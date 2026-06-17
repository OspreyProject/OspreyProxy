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

import lombok.AllArgsConstructor;
import lombok.Getter;
import net.foulest.ospreyproxy.result.LookupResult;
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
@AllArgsConstructor
public enum Descriptor {

    /**
     * OpenPhish
     */
    OPEN_PHISH(
            List.of("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"),
            Format.TEXT,
            "OpenPhish",
            "openphish",
            LookupResult.PHISHING,
            120L,
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
            120L,
            null
    ),

    /**
     * Phishing.Database
     */
    PHISHING_DATABASE(
            List.of("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"),
            Format.TEXT,
            "Phishing.Database",
            "phishing-database",
            LookupResult.PHISHING,
            120L,
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
            120L,
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
            120L,
            null
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
            120L,
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
            120L,
            "THREATFOX_API_KEY"
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
     * URL with the value of this environment variable.
     */
    private final @Nullable String apiKeyEnvVar;

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
