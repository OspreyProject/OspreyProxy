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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.util.check.PreparedUrl;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.*;

/**
 * Turns the per-provider verdicts from one /check fan-out into a single {@link ScanRecord}, and
 * decides whether that scan is trustworthy enough to persist and whether it is severe enough to
 * publish.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ScanAggregator {

    // Only hard, unambiguous detections are ever published as crawlable pages. Soft signals
    // (suspicious, newly registered, dynamic DNS) and clean results are recorded but never indexed,
    // which keeps thin, low-confidence, or easily-disputed pages out of the search index.
    private static final EnumSet<LookupResult> INDEXABLE = EnumSet.of(
            LookupResult.PHISHING,
            LookupResult.MALICIOUS
    );

    /**
     * Builds a durable record from the verdicts of one scan, or returns {@code null} when the scan is
     * not authoritative enough to trust. A scan is non-authoritative when every provider failed or was
     * rate limited, or when more than half of them failed, which usually means the providers were
     * degraded rather than that the URL is clean. Non-authoritative scans are never written, so a
     * provider outage can neither create a misleading record nor launder an existing bad verdict.
     *
     * @param prepared The URL that was scanned.
     * @param verdicts The verdict for every provider that was scanned, keyed by endpoint name.
     * @param now The scan timestamp, in epoch millis.
     * @return The record to persist, or {@code null} if the scan should not be persisted.
     */
    public static @Nullable ScanRecord build(@NonNull PreparedUrl prepared,
                                             @NonNull Map<String, LookupVerdict> verdicts,
                                             long now) {
        int total = verdicts.size();

        if (total == 0) {
            return null;
        }

        int flagged = 0;
        int failed = 0;
        int usable = 0;

        List<LookupResult> primaries = new ArrayList<>(total);
        Map<String, List<String>> results = LinkedHashMap.newLinkedHashMap(total);

        for (Map.Entry<String, LookupVerdict> entry : verdicts.entrySet()) {
            LookupVerdict verdict = entry.getValue();
            results.put(entry.getKey(), verdict.values());
            primaries.add(verdict.primary());

            if (verdict.isFailed()) {
                failed++;
            } else if (!verdict.isRateLimited()) {
                // Rate-limited verdicts are neither usable signal nor a hard failure, so they fall
                // through here and are counted in neither tally.
                usable++;

                if (isFlagged(verdict)) {
                    flagged++;
                }
            }
        }

        // Require at least one usable provider and no more than half failed.
        if (usable == 0 || failed * 2 > total) {
            return null;
        }

        LookupResult primary = LookupVerdict.of(primaries).primary();
        boolean indexable = INDEXABLE.contains(primary);

        return new ScanRecord(
                prepared.canonicalUrl(),
                prepared.host(),
                prepared.bareHost(),
                primary.getValue(),
                results,
                flagged,
                total,
                now,
                now,
                1,
                indexable,
                null
        );
    }

    /**
     * Whether a verdict counts as a detection, mirroring the tally used by the /check summary.
     *
     * @param verdict The verdict to test.
     * @return {@code true} if the verdict is neither allowed, failed, nor rate-limited.
     */
    private static boolean isFlagged(@NonNull LookupVerdict verdict) {
        return !verdict.isAllowedOnly() && !verdict.isFailed() && !verdict.isRateLimited();
    }
}
