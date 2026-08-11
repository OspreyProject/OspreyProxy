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

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;

import java.sql.ResultSet;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * The durable, aggregate scan store backed by SQLite.
 * <p>
 * This sits above the per-provider Caffeine caches. Those caches make a single provider lookup fast
 * and are ephemeral; this store makes a whole /check verdict durable and queryable, keyed by the
 * canonical URL, so a repeat scan can be served without touching any provider and so hard-flagged
 * URLs can be published as crawlable pages.
 * <p>
 * Every method fails soft: a store error is logged and swallowed so a database problem degrades the
 * scanner to its stateless behavior rather than taking it down.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "osprey.store.enabled", havingValue = "true")
public class ScanStore {

    private static final JavaType RESULTS_TYPE = JacksonUtil.MAPPER.constructType(
            new TypeReference<Map<String, List<String>>>() {
            }
    );

    private final JdbcTemplate jdbc;

    // Retention window for non-indexable records; zero or negative disables pruning
    private final long retentionMillis;

    // Maximum records deleted per prune pass
    private final int pruneLimit;

    private final RowMapper<ScanRecord> mapper = (ResultSet rs, int rowNum) -> {
        Map<String, List<String>> results = parseResults(rs.getString("results_json"));
        long published = rs.getLong("published_at");
        Long publishedAt = rs.wasNull() ? null : published;

        return new ScanRecord(
                rs.getString("canonical_url"),
                rs.getString("host"),
                rs.getString("bare_host"),
                rs.getString("primary_result"),
                results,
                rs.getInt("flagged_count"),
                rs.getInt("total_count"),
                rs.getLong("first_scanned_at"),
                rs.getLong("last_scanned_at"),
                rs.getInt("scan_count"),
                rs.getInt("indexable") != 0,
                publishedAt
        );
    };

    /**
     * Constructs the store.
     *
     * @param scanJdbcTemplate The JdbcTemplate bound to the SQLite scan database.
     * @param retentionDays How long a non-indexable record is kept before pruning; zero disables it.
     * @param pruneLimit The maximum number of records deleted per prune pass.
     */
    public ScanStore(@NonNull JdbcTemplate scanJdbcTemplate,
                     @Value("${osprey.store.retention.days:90}") long retentionDays,
                     @Value("${osprey.store.retention.prune-limit:5000}") int pruneLimit) {
        jdbc = scanJdbcTemplate;
        retentionMillis = retentionDays <= 0 ? 0L : Duration.ofDays(retentionDays).toMillis();
        this.pruneLimit = pruneLimit;
    }

    /**
     * Creates the schema on first start if it does not already exist.
     */
    @PostConstruct
    public void init() {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS scan_result (
                    canonical_url    TEXT PRIMARY KEY,
                    host             TEXT NOT NULL,
                    bare_host        TEXT NOT NULL,
                    primary_result   TEXT NOT NULL,
                    results_json     TEXT NOT NULL,
                    flagged_count    INTEGER NOT NULL,
                    total_count      INTEGER NOT NULL,
                    first_scanned_at INTEGER NOT NULL,
                    last_scanned_at  INTEGER NOT NULL,
                    scan_count       INTEGER NOT NULL,
                    indexable        INTEGER NOT NULL DEFAULT 0,
                    published_at     INTEGER
                )
                """);

        jdbc.execute("CREATE INDEX IF NOT EXISTS idx_scan_indexable "
                + "ON scan_result (indexable, last_scanned_at)");

        jdbc.execute("CREATE INDEX IF NOT EXISTS idx_scan_publish "
                + "ON scan_result (indexable, published_at)");

        log.info("[store] Schema ready");
    }

    /**
     * Looks up a stored record by its canonical URL.
     *
     * @param canonicalUrl The canonical {@code https://host/path} key.
     * @return The stored record, or {@code null} if none exists or the lookup failed.
     */
    public @Nullable ScanRecord get(@NonNull String canonicalUrl) {
        try {
            List<ScanRecord> rows = jdbc.query(
                    "SELECT * FROM scan_result WHERE canonical_url = ?", mapper, canonicalUrl);
            return rows.isEmpty() ? null : rows.getFirst();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] get failed: {}", e.getClass().getName());
            return null;
        }
    }

    /**
     * Inserts a new record or updates an existing one for the same canonical URL. On update the
     * first-scanned timestamp is preserved and the scan count is incremented. When the new record is
     * indexable the published timestamp is cleared so the publisher re-announces the fresh verdict.
     *
     * @param scanRecord The record to store.
     */
    public void upsert(@NonNull ScanRecord scanRecord) {
        String resultsJson = writeResults(scanRecord.results());

        try {
            jdbc.update("""
                            INSERT INTO scan_result (canonical_url, host, bare_host, primary_result,
                                results_json, flagged_count, total_count, first_scanned_at,
                                last_scanned_at, scan_count, indexable, published_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NULL)
                            ON CONFLICT(canonical_url) DO UPDATE SET
                                primary_result  = excluded.primary_result,
                                results_json    = excluded.results_json,
                                flagged_count   = excluded.flagged_count,
                                total_count     = excluded.total_count,
                                last_scanned_at = excluded.last_scanned_at,
                                scan_count      = scan_result.scan_count + 1,
                                indexable       = excluded.indexable,
                                published_at    = CASE WHEN excluded.indexable = 1
                                                       THEN NULL ELSE scan_result.published_at END
                            """,
                    scanRecord.canonicalUrl(), scanRecord.host(), scanRecord.bareHost(), scanRecord.primaryResult(),
                    resultsJson, scanRecord.flaggedCount(), scanRecord.totalCount(), scanRecord.firstScannedAt(),
                    scanRecord.lastScannedAt(), scanRecord.indexable() ? 1 : 0);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] upsert failed for {}: {}", scanRecord.canonicalUrl(), e.getClass().getName());
        }
    }

    /**
     * Returns indexable records that have not yet been announced to search engines.
     *
     * @param limit The maximum number of records to return.
     * @return Unpublished indexable records, oldest first.
     */
    public @NonNull List<ScanRecord> findUnpublished(int limit) {
        try {
            return jdbc.query("""
                    SELECT * FROM scan_result
                    WHERE indexable = 1 AND published_at IS NULL
                    ORDER BY last_scanned_at ASC
                    LIMIT ?
                    """, mapper, limit);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] findUnpublished failed: {}", e.getClass().getName());
            return List.of();
        }
    }

    /**
     * Returns indexable records last scanned at or after the given time, for the build-time page feed.
     *
     * @param sinceMillis Lower bound on {@code last_scanned_at}, in epoch millis.
     * @param limit The maximum number of records to return.
     * @return Matching indexable records, most recently scanned first.
     */
    public @NonNull List<ScanRecord> findIndexableSince(long sinceMillis, int limit) {
        try {
            return jdbc.query("""
                    SELECT * FROM scan_result
                    WHERE indexable = 1 AND last_scanned_at >= ?
                    ORDER BY last_scanned_at DESC
                    LIMIT ?
                    """, mapper, sinceMillis, limit);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] findIndexableSince failed: {}", e.getClass().getName());
            return List.of();
        }
    }

    /**
     * Deletes non-indexable records last scanned before the cutoff, up to a bounded batch size.
     * Indexable records are never pruned, since they back crawlable pages.
     *
     * @param cutoffMillis Delete records last scanned before this epoch-millis value.
     * @param limit The maximum number of records to delete in one call.
     * @return The number of records deleted.
     */
    public int pruneStale(long cutoffMillis, int limit) {
        try {
            return jdbc.update("""
                    DELETE FROM scan_result
                    WHERE canonical_url IN (
                        SELECT canonical_url FROM scan_result
                        WHERE indexable = 0 AND last_scanned_at < ?
                        ORDER BY last_scanned_at ASC
                        LIMIT ?
                    )
                    """, cutoffMillis, limit);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] pruneStale failed: {}", e.getClass().getName());
            return 0;
        }
    }

    /**
     * Periodically prunes stale non-indexable records. Disabled when retention is zero or negative.
     */
    @Scheduled(initialDelayString = "${osprey.store.retention.initial-delay-millis:600000}",
            fixedDelayString = "${osprey.store.retention.interval-millis:86400000}")
    public void pruneScheduled() {
        if (retentionMillis <= 0L) {
            return;
        }

        int deleted = pruneStale(System.currentTimeMillis() - retentionMillis, pruneLimit);

        if (deleted > 0) {
            log.info("[store] Pruned {} stale record(s)", deleted);
        }
    }

    /**
     * Marks a batch of records as announced to search engines.
     *
     * @param canonicalUrls The canonical URLs to mark.
     * @param timestamp The publish timestamp, in epoch millis.
     */
    public void markPublished(@NonNull Collection<String> canonicalUrls, long timestamp) {
        if (canonicalUrls.isEmpty()) {
            return;
        }

        try {
            jdbc.batchUpdate("UPDATE scan_result SET published_at = ? WHERE canonical_url = ?",
                    canonicalUrls.stream()
                            .map(url -> new Object[]{timestamp, url})
                            .toList());
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] markPublished failed: {}", e.getClass().getName());
        }
    }

    /**
     * Parses a stored results JSON blob, returning an empty map on any error.
     *
     * @param json The stored JSON.
     * @return The parsed per-provider results map.
     */
    private static @NonNull Map<String, List<String>> parseResults(@Nullable String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }

        try {
            return JacksonUtil.MAPPER.readValue(json, RESULTS_TYPE);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] Failed to parse results JSON: {}", e.getClass().getName());
            return Map.of();
        }
    }

    /**
     * Serializes a per-provider results map to JSON, falling back to an empty object on error.
     *
     * @param results The results map.
     * @return The serialized JSON.
     */
    private static @NonNull String writeResults(@NonNull Map<String, List<String>> results) {
        try {
            return JacksonUtil.MAPPER.writeValueAsString(results);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[store] Failed to serialize results JSON: {}", e.getClass().getName());
            return "{}";
        }
    }
}
