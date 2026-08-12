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
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import net.foulest.ospreyproxy.util.reporting.ReceivedPayload;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.JsonNode;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.regex.Pattern;

/**
 * Throwaway reference receiver for the extension's {@code ReportingEndpoint} policy, backing the
 * "check my reporting setup" page on the website.
 * <p>
 * An MSP technician opens the site page, which generates a random session token and shows the URL
 * {@code /reporting/test/{token}}. The technician sets that URL as the {@code ReportingEndpoint} on a
 * pilot endpoint; the extension POSTs its event batches and heartbeats here, and the page polls
 * {@code GET /reporting/test/{token}} to display and validate what arrived. Nothing is persisted:
 * payloads live in a small in-memory ring per token and the whole session evaporates minutes after
 * the last touch. This is a configuration checker, not a place to point a production fleet.
 * <p>
 * The token is never issued by the server. The page invents it client-side, so an unused token holds
 * no state and a GET for it simply returns an empty list. Bodies must be valid JSON and are stored
 * verbatim; validation of the reporting schema happens on the page, keeping this endpoint dumb.
 */
@Slf4j
@RestController
@ConditionalOnProperty(name = "osprey.reporting-test.enabled", havingValue = "true", matchIfMissing = true)
public class ReportingTestHandler {

    // Tokens are page-generated (crypto.randomUUID or similar); constrain the shape so the path
    // cannot be abused as arbitrary keyspace.
    private static final Pattern TOKEN_PATTERN = Pattern.compile("[A-Za-z0-9-]{16,64}");

    // One stored payload's raw JSON is capped here, matching the SecurityFilter's reporting-test
    // body ceiling so nothing the filter admits is rejected here.
    private static final int MAX_PAYLOAD_BYTES = 262_144;

    // Most recent payloads kept per session; a fresh pilot endpoint sends far fewer.
    private static final int MAX_PAYLOADS_PER_SESSION = 30;

    // Sessions keyed by token, evicted shortly after the page stops polling. Bounded so the
    // public deployment cannot be grown without limit.
    private final Cache<String, Deque<ReceivedPayload>> sessions;

    // Per-IP buckets so one caller cannot spray the endpoint
    private final Cache<String, Bucket> ipBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(20_000)
            .build();

    private final Bandwidth ipBandwidth;

    /**
     * @param sessionTtlMinutes Minutes an idle session (no POST and no poll) survives before eviction.
     * @param maxSessions Maximum concurrent sessions held in memory.
     * @param rateCapacity Requests one IP may make per rate window, across POST and GET combined.
     * @param rateWindowSeconds The rate window length in seconds.
     */
    public ReportingTestHandler(@Value("${osprey.reporting-test.session-ttl-minutes:30}") long sessionTtlMinutes,
                                @Value("${osprey.reporting-test.max-sessions:300}") long maxSessions,
                                @Value("${osprey.reporting-test.rate.capacity:120}") long rateCapacity,
                                @Value("${osprey.reporting-test.rate.window-seconds:60}") long rateWindowSeconds) {
        sessions = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(sessionTtlMinutes))
                .maximumSize(maxSessions)
                .build();

        ipBandwidth = Bandwidth.builder()
                .capacity(rateCapacity)
                .refillGreedy(rateCapacity, Duration.ofSeconds(rateWindowSeconds))
                .build();
    }

    /**
     * Receives one reporting POST (an event batch or a heartbeat) for a session and stores it.
     * Mirrors what a real receiver should do: accept JSON, return 2xx. A non-2xx other than 429 is
     * treated as a permanent rejection by the extension, so malformed input gets 400.
     *
     * @param token The page-generated session token from the path.
     * @param body The raw JSON body the extension sent.
     * @param request The incoming request, for the Authorization check and rate limiting.
     * @return {@code 200 {"ok":true}} on success.
     */
    @PostMapping(value = "/reporting/test/{token}", produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> receive(@PathVariable @NonNull String token,
                                                   @RequestBody @NonNull String body,
                                                   @NonNull HttpServletRequest request) {
        ResponseEntity<String> rejection = reject(token, request);

        if (rejection != null) {
            return rejection;
        }

        if (body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_PAYLOAD_BYTES) {
            return ErrorUtil.RESP_400;
        }

        // Must parse as JSON; stored verbatim so the page sees exactly what the extension sent
        try {
            JsonNode ignored = JacksonUtil.MAPPER.readTree(body);
        } catch (Exception ex) {
            log.warn("Rejected reporting-test payload that is not valid JSON");
            return ErrorUtil.RESP_400;
        }

        boolean authPresent = request.getHeader(HttpHeaders.AUTHORIZATION) != null;
        ReceivedPayload payload = new ReceivedPayload(System.currentTimeMillis(), authPresent, body);

        Deque<ReceivedPayload> deque = sessions.get(token, ignored -> new ArrayDeque<>());

        synchronized (deque) {
            deque.addLast(payload);

            while (deque.size() > MAX_PAYLOADS_PER_SESSION) {
                deque.removeFirst();
            }
        }
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body("{\"ok\":true}");
    }

    /**
     * Returns everything received for a session, oldest first, for the site page to poll. A token
     * nothing has posted to yet returns an empty list rather than an error, since the page starts
     * polling before the technician has finished configuring the endpoint.
     *
     * @param token The page-generated session token from the path.
     * @param request The incoming request, for rate limiting.
     * @return {@code {"payloads":[{"receivedAt":...,"authPresent":...,"body":{...}}, ...]}}
     */
    @GetMapping(value = "/reporting/test/{token}", produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> poll(@PathVariable @NonNull String token,
                                                @NonNull HttpServletRequest request) {
        ResponseEntity<String> rejection = reject(token, request);

        if (rejection != null) {
            return rejection;
        }

        Deque<ReceivedPayload> deque = sessions.getIfPresent(token);
        StringBuilder out = new StringBuilder(256);
        out.append("{\"payloads\":[");

        if (deque != null) {
            synchronized (deque) {
                boolean first = true;

                for (ReceivedPayload payload : deque) {
                    if (!first) {
                        out.append(',');
                    }

                    first = false;

                    out.append("{\"receivedAt\":").append(payload.receivedAt())
                            .append(",\"authPresent\":").append(payload.authPresent())
                            .append(",\"body\":").append(payload.rawJson())
                            .append('}');
                }
            }
        }

        out.append("]}");
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(out.toString());
    }

    /**
     * Shared token and rate-limit gate for both verbs.
     *
     * @param token The session token from the path.
     * @param request The incoming request.
     * @return An error response to return, or {@code null} when the request may proceed.
     */
    private @Nullable ResponseEntity<String> reject(@NonNull String token, @NonNull HttpServletRequest request) {
        if (!TOKEN_PATTERN.matcher(token).matches()) {
            return ErrorUtil.RESP_400;
        }

        String hashedIp = RequestUtil.hashClientIp(request, "reporting-test");
        Bucket bucket = ipBuckets.get(hashedIp, ignored -> Bucket.builder().addLimit(ipBandwidth).build());

        if (!bucket.tryConsume(1)) {
            return ErrorUtil.RESP_429;
        }
        return null;
    }
}
