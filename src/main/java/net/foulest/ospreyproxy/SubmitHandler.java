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
import net.foulest.ospreyproxy.tenant.Tenant;
import net.foulest.ospreyproxy.tenant.TenantService;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import net.foulest.ospreyproxy.util.list.Descriptor;
import net.foulest.ospreyproxy.util.list.LocalListUtil;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Accepts bulk link submissions from feed partners into a file-backed submission feed.
 * <p>
 * {@code POST /submit/{providerId}} takes a JSON body {@code {"urls": ["...", ...]}} and requires
 * {@code Authorization: Bearer <token>}. Tokens live in the tenant key store under the tenant id
 * {@code submit-<endpointName>}, so they are held only as SHA-256 hashes, hot-reload, rotate with
 * overlap, and revoke without a restart. The presented token must resolve to the tenant that matches
 * the provider id in the path, so a token only ever authorizes writes to the one feed it was issued
 * for. Accepted entries are appended to that feed's text file and published to the in-memory set
 * immediately; duplicates are counted but never written twice.
 * <p>
 * A stolen token is contained by: per-IP throttling before authentication, the tenant's own request
 * budget, a daily accepted-entry budget per feed, per-entry and per-file size caps, and a protected
 * domain list. Every submission is logged with feed, hashed source address, and counts.
 */
@Slf4j
@RestController
public class SubmitHandler {

    private static final String CONTEXT = "submit";
    private static final String BEARER_PREFIX = "Bearer ";

    private final TenantService tenantService;
    private final Bandwidth ipBandwidth;
    private final Bandwidth dailyBandwidth;
    private final int maxEntries;

    // Per-IP limiter applied before authentication, so token guessing is throttled.
    private final Cache<String, Bucket> ipBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(20_000)
            .build();

    // Per-feed daily budget of accepted entries, so a stolen token cannot poison a feed en masse.
    private final Cache<String, Bucket> dailyBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofDays(2))
            .maximumSize(64)
            .build();

    /**
     * Creates the handler with its rate budgets from configuration.
     *
     * @param tenantService Resolves bearer tokens against the hot-reloaded tenant key store.
     * @param ipCapacity Requests allowed per IP within the window, before authentication.
     * @param windowSeconds Refill window for the per-IP budget, in seconds.
     * @param dailyEntries Accepted entries allowed per feed per day.
     * @param maxEntries Maximum number of entries accepted in one body.
     */
    public SubmitHandler(@NonNull TenantService tenantService,
                         @Value("${osprey.submissions.rate.ip-capacity:30}") long ipCapacity,
                         @Value("${osprey.submissions.rate.window-seconds:60}") long windowSeconds,
                         @Value("${osprey.submissions.daily-entries:5000}") long dailyEntries,
                         @Value("${osprey.submissions.max-entries:1000}") int maxEntries) {
        this.tenantService = tenantService;

        // A batch larger than the daily budget could never be accepted, so clamp to keep the two coherent.
        this.maxEntries = (int) Math.max(1L, Math.min(maxEntries, dailyEntries));

        ipBandwidth = Bandwidth.builder()
                .capacity(ipCapacity)
                .refillGreedy(ipCapacity, Duration.ofSeconds(windowSeconds))
                .build();

        dailyBandwidth = Bandwidth.builder()
                .capacity(dailyEntries)
                .refillIntervally(dailyEntries, Duration.ofDays(1))
                .build();
    }

    /**
     * Submits links to the named feed.
     *
     * @param providerId The feed's endpoint name, e.g. {@code acomics}.
     * @param authorization The {@code Authorization} header carrying the feed's bearer token.
     * @param bodyBytes The raw JSON body holding a {@code urls} array of strings. Taken as bytes so it
     *                  is not parsed until the caller has passed rate limiting and authentication.
     * @param request The incoming request, for per-IP rate limiting and audit logging.
     * @return A JSON body with {@code accepted}, {@code duplicates}, and {@code rejected} counts.
     */
    @PostMapping(value = "/submit/{providerId}", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> submit(@PathVariable String providerId,
                                                  @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
                                                  @Nullable String authorization,
                                                  @RequestBody(required = false) byte @Nullable [] bodyBytes,
                                                  @NonNull HttpServletRequest request) {
        String hashedIp = RequestUtil.hashClientIp(request, CONTEXT);
        Bucket ipBucket = ipBuckets.get(hashedIp, ignored -> Bucket.builder().addLimit(ipBandwidth).build());

        if (!ipBucket.tryConsume(1)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // The token is looked up by SHA-256 hash in the tenant store (a constant-time map lookup on a
        // digest, never a string compare on the secret) and must resolve to the tenant for exactly the
        // feed named in the path. Every failure (unknown feed, non-submission feed, missing, invalid, or
        // wrong-feed token) returns the same 401, so an unauthenticated caller cannot enumerate which
        // feeds accept submissions. A feed with no keys in the store fails closed.
        String presented = authorization != null && authorization.startsWith(BEARER_PREFIX)
                ? authorization.substring(BEARER_PREFIX.length()) : null;

        Tenant tenant = tenantService.resolve(presented);
        Descriptor descriptor = LocalListUtil.findByEndpointName(providerId);

        if (tenant == null
                || descriptor == null
                || !descriptor.isSubmissionFeed()
                || !(TenantService.SUBMIT_TENANT_PREFIX + descriptor.getEndpointName()).equals(tenant.id())) {
            log.warn("[submit] Rejected: unknown feed or missing, invalid, or wrong-feed bearer token (ip {})",
                    hashedIp
            );
            throw new StatusCodeException(ErrorUtil.RESP_401);
        }

        // The tenant's own burst and sustained request budget from the store applies to submissions.
        if (!tenant.tryConsume()) {
            log.warn("[{}] Submission rate budget exhausted", descriptor.getShortName());
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // Only an authenticated, in-budget caller gets to spend parser time on a 256 KB body.
        Map<String, Object> body;

        try {
            body = bodyBytes == null || bodyBytes.length == 0 ? Map.of()
                    : JacksonUtil.MAPPER.readValue(bodyBytes, JacksonUtil.MAP_TYPE_OBJECT);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        Object urlsValue = body.get("urls");

        if (!(urlsValue instanceof List<?> rawList) || rawList.isEmpty() || rawList.size() > maxEntries) {
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Shape-check the batch before touching the daily budget, so a malformed body costs nothing.
        List<String> entries = new ArrayList<>(rawList.size());

        for (Object element : rawList) {
            if (!(element instanceof String entry)) {
                throw new StatusCodeException(ErrorUtil.RESP_400);
            }

            entries.add(entry);
        }

        // Daily accepted-entry budget: reserve room for the whole batch up front so a stolen token can
        // add at most this many entries per day before the operator notices the log line.
        Bucket dailyBucket = dailyBuckets.get(descriptor.getEndpointName(),
                ignored -> Bucket.builder().addLimit(dailyBandwidth).build());

        if (!dailyBucket.tryConsume(entries.size())) {
            log.warn("[{}] Daily submission budget exhausted; refusing {} entries (ip {})",
                    descriptor.getShortName(), entries.size(), hashedIp
            );
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        Map<String, Integer> counts;
        int accepted = 0;

        try {
            counts = LocalListUtil.submit(descriptor, entries, hashedIp);
            accepted = counts.getOrDefault("accepted", 0);
        } catch (IOException e) {
            log.error("[{}] Failed to persist submission: {}",
                    descriptor.getShortName(), e.getClass().getName(), e
            );
            throw new StatusCodeException(ErrorUtil.RESP_500);
        } finally {
            // Only entries actually written spend budget; duplicates, rejects, and failed writes are refunded.
            long unused = (long) entries.size() - accepted;

            if (unused > 0L) {
                dailyBucket.addTokens(unused);
            }
        }

        // Anomaly signal: one batch consuming a large share of the day's budget is what a stolen token
        // looks like, so surface it at WARN where log monitoring will see it.
        if (accepted > 0 && accepted * 5L >= dailyBandwidth.getCapacity()) {
            log.warn("[{}] Large submission batch: {} entries accepted in one request (ip {})",
                    descriptor.getShortName(), accepted, hashedIp);
        }

        // Audit trail: feed, hashed source, and counts only. Submitted URLs and tokens are never logged.
        log.warn("[{}] Submission from {}: accepted {}, duplicates {}, rejected {}",
                descriptor.getShortName(), hashedIp,
                counts.get("accepted"), counts.get("duplicates"), counts.get("rejected")
        );

        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(JacksonUtil.MAPPER.writeValueAsString(counts));
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Failed to serialize submission result: {}",
                    descriptor.getShortName(), e.getClass().getName()
            );
            return ErrorUtil.RESP_500;
        }
    }
}
