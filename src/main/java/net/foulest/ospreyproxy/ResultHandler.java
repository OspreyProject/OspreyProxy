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
package net.foulest.ospreyproxy;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.store.ScanRecord;
import net.foulest.ospreyproxy.store.ScanStore;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import net.foulest.ospreyproxy.util.check.PreparedUrl;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only endpoints over the durable scan store.
 * <p>
 * {@code GET /result} lets the public checker page look up a stored verdict for a URL without
 * running a scan, so a repeat visit renders instantly and shows when the URL was last checked. It
 * takes no captcha because it never contacts a provider, but it is still per-IP rate limited.
 * <p>
 * {@code GET /internal/index-feed} lets the site build fetch the set of hard-flagged URLs that
 * should have crawlable pages. It is gated by a shared secret and is never exposed cross-origin.
 * <p>
 * Both endpoints exist only when the store is enabled.
 */
@Slf4j
@RestController
@ConditionalOnBean(ScanStore.class)
public class ResultHandler {

    private static final String CONTEXT = "result";

    private final ScanStore store;
    private final CheckHandler checkHandler;
    private final long freshnessMillis;
    private final String feedToken;
    private final int feedLimit;

    // Per-IP limiter for the public result lookup, evicted after an hour of inactivity.
    private final Bandwidth resultBandwidth;
    private final Cache<String, Bucket> resultBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(20_000)
            .build();

    /**
     * Constructs the read-only handler.
     *
     * @param store The durable scan store.
     * @param checkHandler The check handler, reused for its URL preparation.
     * @param freshnessSeconds How long a stored scan is considered fresh, in seconds.
     * @param feedToken The shared secret required to read the internal index feed.
     * @param feedLimit The maximum number of records returned by the index feed.
     * @param rateCapacity Per-IP result-lookup token capacity.
     * @param rateWindowSeconds Per-IP result-lookup refill window, in seconds.
     */
    public ResultHandler(@NonNull ScanStore store,
                         @NonNull CheckHandler checkHandler,
                         @Value("${osprey.store.freshness-seconds:86400}") long freshnessSeconds,
                         @Value("${osprey.store.index-feed.token:}") String feedToken,
                         @Value("${osprey.store.index-feed.limit:5000}") int feedLimit,
                         @Value("${osprey.store.result.rate-capacity:30}") long rateCapacity,
                         @Value("${osprey.store.result.rate-window-seconds:60}") long rateWindowSeconds) {
        this.store = store;
        this.checkHandler = checkHandler;
        freshnessMillis = Duration.ofSeconds(freshnessSeconds).toMillis();
        this.feedToken = feedToken;
        this.feedLimit = feedLimit;

        resultBandwidth = Bandwidth.builder()
                .capacity(rateCapacity)
                .refillGreedy(rateCapacity, Duration.ofSeconds(rateWindowSeconds))
                .build();
    }

    /**
     * Returns the stored verdict for a URL, if one exists. Never scans.
     *
     * @param url The raw URL to look up.
     * @param request The incoming request, used for per-IP rate limiting.
     * @return A JSON body describing the stored verdict, or {@code found: false} when none exists.
     */
    @GetMapping(value = "/result", produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> result(@RequestParam(required = false) String url,
                                                  @NonNull HttpServletRequest request) {
        String hashedIp = RequestUtil.hashClientIp(request, CONTEXT);

        if (!bucket(hashedIp).tryConsume(1)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        PreparedUrl prepared = CheckHandler.prepare(url);

        if (prepared == null) {
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        ScanRecord scanRecord = store.get(prepared.canonicalUrl());

        if (scanRecord == null) {
            Map<String, Object> body = LinkedHashMap.newLinkedHashMap(2);
            body.put("found", false);
            body.put("url", prepared.canonicalUrl());
            return json(body);
        }

        boolean fresh = System.currentTimeMillis() - scanRecord.lastScannedAt() < freshnessMillis;
        return json(toJson(scanRecord, fresh));
    }

    /**
     * Returns the set of hard-flagged URLs that should have crawlable pages. Gated by a shared secret.
     *
     * @param authorization The {@code Authorization} header carrying the shared secret.
     * @param since Optional lower bound on the last-scanned time, in epoch millis.
     * @return A JSON body carrying the indexable records, or a 404 when the secret is missing or wrong.
     */
    @GetMapping(value = "/internal/index-feed", produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> indexFeed(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long since) {
        // The feed is invisible unless a secret is configured and matches exactly. A wrong or missing
        // secret returns 404 rather than 403 so the endpoint's existence is not confirmed to probers
        if (feedToken.isBlank() || !constantTimeEquals(authorization, "Bearer " + feedToken)) {
            throw new StatusCodeException(ErrorUtil.RESP_404);
        }

        long sinceMillis = since == null ? 0L : since;
        List<ScanRecord> records = store.findIndexableSince(sinceMillis, feedLimit);

        List<Map<String, Object>> items = new ArrayList<>(records.size());

        for (ScanRecord scanRecord : records) {
            items.add(toJson(scanRecord, true));
        }

        Map<String, Object> body = LinkedHashMap.newLinkedHashMap(2);
        body.put("count", items.size());
        body.put("results", items);
        return json(body);
    }

    /**
     * Compares two strings without early-exit timing leakage. Reveals length but not content,
     * which is acceptable for a fixed-length bearer token.
     *
     * @param actual The caller-supplied value, or {@code null}.
     * @param expected The expected value.
     * @return {@code true} if the two strings are equal.
     */
    private static boolean constantTimeEquals(@Nullable String actual, @NonNull String expected) {
        if (actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Serializes a body map to a JSON response, or a 500 on serialization failure.
     *
     * @param body The response body map.
     * @return A JSON response entity.
     */
    private static @NonNull ResponseEntity<String> json(@NonNull Map<String, Object> body) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(JacksonUtil.MAPPER.writeValueAsString(body));
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to serialize response: {}", CONTEXT, e.getClass().getName());
            throw new StatusCodeException(ErrorUtil.RESP_500);
        }
    }

    /**
     * Serializes a record for the JSON responses.
     *
     * @param scanRecord The record to serialize.
     * @param fresh Whether the record is within the freshness window.
     * @return An ordered JSON-ready map.
     */
    private static @NonNull Map<String, Object> toJson(@NonNull ScanRecord scanRecord, boolean fresh) {
        Map<String, Object> body = LinkedHashMap.newLinkedHashMap(10);
        body.put("found", true);
        body.put("url", scanRecord.canonicalUrl());
        body.put("host", scanRecord.host());
        body.put("primary", scanRecord.primaryResult());
        body.put("flagged", scanRecord.flaggedCount());
        body.put("total", scanRecord.totalCount());
        body.put("results", scanRecord.results());
        body.put("lastScanned", scanRecord.lastScannedAt());
        body.put("firstScanned", scanRecord.firstScannedAt());
        body.put("fresh", fresh);
        return body;
    }

    /**
     * Fetches a per-IP bucket, creating it on first use.
     *
     * @param key The hashed IP key.
     * @return The bucket for this IP.
     */
    private @NonNull Bucket bucket(@NonNull String key) {
        return resultBuckets.get(key, ignored -> Bucket.builder().addLimit(resultBandwidth).build());
    }
}
