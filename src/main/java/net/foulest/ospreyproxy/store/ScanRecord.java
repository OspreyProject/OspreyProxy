/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
package net.foulest.ospreyproxy.store;

import org.jspecify.annotations.NonNull;

import java.util.List;
import java.util.Map;

/**
 * One durable, aggregate scan of a single canonical URL.
 * <p>
 * The key is {@code canonicalUrl}: the {@code https://host/path} form produced by the /check
 * endpoint, with the scheme forced to https, a leading {@code www.} removed, and the query and
 * fragment dropped. The path is kept, so distinct pages on a shared host (for example a specific
 * form on a form-builder) are recorded separately rather than collapsed to the bare host.
 *
 * @param canonicalUrl The canonical {@code https://host/path} key.
 * @param host The normalized, ASCII, lowercased host.
 * @param bareHost The registrable domain (eTLD+1) of {@code host}.
 * @param primaryResult The most severe result across all providers, as a {@link net.foulest.ospreyproxy.result.LookupResult} value string.
 * @param results Per-provider results, keyed by provider endpoint name, each a severity-ordered list of result value strings.
 * @param flaggedCount The number of providers that flagged this URL.
 * @param totalCount The number of providers scanned.
 * @param firstScannedAt Epoch millis of the first scan.
 * @param lastScannedAt Epoch millis of the most recent scan.
 * @param scanCount The number of times this URL has been scanned.
 * @param indexable Whether this record is eligible to be published as a crawlable page.
 * @param publishedAt Epoch millis the record was last submitted to search engines, or {@code null} if never.
 */
public record ScanRecord(@NonNull String canonicalUrl,
                         @NonNull String host,
                         @NonNull String bareHost,
                         @NonNull String primaryResult,
                         @NonNull Map<String, List<String>> results,
                         int flaggedCount,
                         int totalCount,
                         long firstScannedAt,
                         long lastScannedAt,
                         int scanCount,
                         boolean indexable,
                         Long publishedAt) {

    /**
     * @return The public, crawlable page URL for this record on the marketing site,
     *         of the form {@code https://osprey.ac/check/<host><path>/}.
     */
    public @NonNull String pageUrl() {
        // canonicalUrl is https://host/path; drop the scheme and rebuild under /check/.
        String withoutScheme = canonicalUrl.substring("https://".length());
        return "https://osprey.ac/check/" + withoutScheme + "/";
    }
}
