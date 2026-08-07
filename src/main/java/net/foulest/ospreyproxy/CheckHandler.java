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
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import net.foulest.ospreyproxy.util.NetworkUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import net.foulest.ospreyproxy.util.check.CheckRequest;
import net.foulest.ospreyproxy.util.check.IndexedVerdict;
import net.foulest.ospreyproxy.util.check.PreparedUrl;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.OutputStream;
import java.net.IDN;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * Public URL-checking aggregator behind {@code osprey.ac/check}.
 * <p>
 * A single POST fans out to every enabled provider and streams one NDJSON line per verdict as it
 * lands, so the page fills in progressively like a multi-vendor scanner. This endpoint is the only
 * browser-facing surface: the per-provider endpoints stay reachable only by the extension. Because
 * one call touches every provider, the endpoint is gated by its own captcha and its own stricter
 * per-IP and global rate limits, and it delegates the actual per-provider work to
 * {@link ProxyHandler#resolveForCheck} so caching, coalescing, and circuit breaking are shared with
 * the extension path rather than duplicated.
 */
@Slf4j
@RestController
public class CheckHandler {

    // NDJSON: one JSON object per line. Not a registered MediaType constant, so it is built once here
    private static final MediaType NDJSON = MediaType.parseMediaType("application/x-ndjson");

    // Context label used for IP-hash log correlation, mirroring the provider-name label elsewhere
    private static final String CONTEXT = "check";
    private static final Pattern HTTPS_PATTERN = Pattern.compile("(?i)^https?://.*");

    private final ProxyHandler proxyHandler;
    private final List<Provider> providers;

    // Turnstile config
    private final boolean turnstileEnabled;
    private final String turnstileSecret;
    private final String turnstileVerifyUrl;
    private final HttpClient turnstileClient;

    // Per-IP rate-limit definitions and a global limiter shared across all callers
    private final Bandwidth burstBandwidth;
    private final Bandwidth sustainedBandwidth;
    private final Bucket globalBucket;

    // Per-IP token buckets, evicted after an hour of inactivity
    private final Cache<String, Bucket> burstBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(20_000)
            .build();
    private final Cache<String, Bucket> sustainedBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(20_000)
            .build();

    // Hard deadline for a single scan; providers still pending past this are reported as failed
    private final long deadlineMillis;

    /**
     * Constructs the aggregator, wiring in the shared proxy logic and reading its own configuration.
     *
     * @param proxyHandler The shared per-provider resolution logic.
     * @param providers All registered providers, injected by Spring.
     * @param turnstileEnabled Whether captcha verification is enforced.
     * @param turnstileSecret The Cloudflare Turnstile secret key.
     * @param turnstileVerifyUrl The Turnstile siteverify URL.
     * @param turnstileTimeoutSeconds The Turnstile verification request timeout, in seconds.
     * @param burstCapacity Per-IP burst token capacity.
     * @param burstWindowSeconds Per-IP burst refill window, in seconds.
     * @param sustainedCapacity Per-IP sustained token capacity.
     * @param sustainedWindowSeconds Per-IP sustained refill window, in seconds.
     * @param globalCapacity Global token capacity across all callers.
     * @param globalWindowSeconds Global refill window, in seconds.
     * @param deadlineSeconds Hard per-scan deadline, in seconds.
     */
    public CheckHandler(@NonNull ProxyHandler proxyHandler,
                        @NonNull List<Provider> providers,
                        @Value("${osprey.check.turnstile.enabled:false}") boolean turnstileEnabled,
                        @Value("${osprey.check.turnstile.secret:}") String turnstileSecret,
                        @Value("${osprey.check.turnstile.verify-url:https://challenges.cloudflare.com/turnstile/v0/siteverify}") String turnstileVerifyUrl,
                        @Value("${osprey.check.turnstile.timeout-seconds:5}") long turnstileTimeoutSeconds,
                        @Value("${osprey.check.rate.burst-capacity:5}") long burstCapacity,
                        @Value("${osprey.check.rate.burst-window-seconds:20}") long burstWindowSeconds,
                        @Value("${osprey.check.rate.sustained-capacity:40}") long sustainedCapacity,
                        @Value("${osprey.check.rate.sustained-window-seconds:3600}") long sustainedWindowSeconds,
                        @Value("${osprey.check.rate.global-capacity:240}") long globalCapacity,
                        @Value("${osprey.check.rate.global-window-seconds:60}") long globalWindowSeconds,
                        @Value("${osprey.check.deadline-seconds:12}") long deadlineSeconds) {
        this.proxyHandler = proxyHandler;
        this.providers = List.copyOf(providers);

        this.turnstileEnabled = turnstileEnabled;
        this.turnstileSecret = turnstileSecret;
        this.turnstileVerifyUrl = turnstileVerifyUrl;

        turnstileClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(turnstileTimeoutSeconds))
                .build();

        burstBandwidth = Bandwidth.builder()
                .capacity(burstCapacity)
                .refillGreedy(burstCapacity, Duration.ofSeconds(burstWindowSeconds))
                .build();

        sustainedBandwidth = Bandwidth.builder()
                .capacity(sustainedCapacity)
                .refillGreedy(sustainedCapacity, Duration.ofSeconds(sustainedWindowSeconds))
                .build();

        globalBucket = Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(globalCapacity)
                        .refillGreedy(globalCapacity, Duration.ofSeconds(globalWindowSeconds))
                        .build())
                .build();

        deadlineMillis = Duration.ofSeconds(deadlineSeconds).toMillis();

        if (turnstileEnabled && turnstileSecret.isBlank()) {
            log.warn("[check] Turnstile is enabled but no secret is configured; all scans will be rejected");
        }
    }

    /**
     * Handles a scan request. Runs all gating synchronously, then returns a streaming body that
     * fans out to every enabled provider and emits one NDJSON line per verdict.
     *
     * @param body The request body carrying the URL and captcha token.
     * @param request The incoming servlet request, used for IP extraction and captcha remote IP.
     * @return A streaming NDJSON response.
     */
    @PostMapping(value = "/check",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = "application/x-ndjson")
    public ResponseEntity<StreamingResponseBody> check(@RequestBody(required = false) CheckRequest body,
                                                       @NonNull HttpServletRequest request) {
        String hashedIp = RequestUtil.hashClientIp(request, CONTEXT);

        // Global limiter first, then per-IP burst and sustained limiters
        if (!globalBucket.tryConsume(1)
                || !bucket(burstBuckets, hashedIp, burstBandwidth).tryConsume(1)
                || !bucket(sustainedBuckets, hashedIp, sustainedBandwidth).tryConsume(1)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        String url = body == null ? null : body.url();
        String token = body == null ? null : body.token();

        // Captcha must pass before any provider is contacted
        if (!verifyTurnstile(token, request)) {
            throw new StatusCodeException(ErrorUtil.RESP_403);
        }

        PreparedUrl prepared = prepareUrl(url);

        if (prepared == null) {
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        List<Provider> active = new ArrayList<>(providers.size());

        for (Provider provider : providers) {
            if (provider.isEnabled()) {
                active.add(provider);
            }
        }

        StreamingResponseBody stream = out -> streamResults(out, active, prepared);

        return ResponseEntity.ok()
                .contentType(NDJSON)
                .header("X-Accel-Buffering", "no")
                .body(stream);
    }

    /**
     * Streams the meta line, one result line per provider as verdicts arrive, and a final done line.
     *
     * @param out The response output stream.
     * @param active The enabled providers to scan.
     * @param prepared The prepared URL.
     */
    private void streamResults(@NonNull OutputStream out,
                               @NonNull List<Provider> active,
                               @NonNull PreparedUrl prepared) {
        boolean[] reported = new boolean[active.size()];

        List<String> endpointNames = new ArrayList<>(active.size());

        for (Provider provider : active) {
            endpointNames.add(provider.getEndpointName());
        }

        Map<String, Object> meta = LinkedHashMap.newLinkedHashMap(4);
        meta.put("type", "meta");
        meta.put("url", prepared.canonicalUrl());
        meta.put("count", active.size());
        meta.put("providers", endpointNames);
        writeLine(out, meta);

        int flagged = 0;

        // Per-request virtual-thread pool: one task per provider, results consumed as they complete
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            ExecutorCompletionService<IndexedVerdict> completion = new ExecutorCompletionService<>(pool);

            for (int i = 0; i < active.size(); i++) {
                Provider provider = active.get(i);
                int index = i;
                completion.submit(() -> new IndexedVerdict(index, safeResolve(provider, prepared)));
            }

            long deadline = System.nanoTime() + Duration.ofMillis(deadlineMillis).toNanos();

            for (int done = 0; done < active.size(); done++) {
                long remaining = deadline - System.nanoTime();

                if (remaining <= 0L) {
                    break;
                }

                Future<IndexedVerdict> future = completion.poll(remaining, TimeUnit.NANOSECONDS);

                // Deadline reached before this result arrived; stragglers are filled in below
                if (future == null) {
                    break;
                }

                IndexedVerdict result = safeGet(future);

                if (result == null) {
                    continue;
                }

                reported[result.index()] = true;
                LookupVerdict verdict = result.verdict();
                Provider provider = active.get(result.index());

                if (isFlagged(verdict)) {
                    flagged++;
                }

                writeResult(out, provider.getEndpointName(), verdict);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Any provider that did not report before the deadline is shown as failed
        for (int i = 0; i < active.size(); i++) {
            if (!reported[i]) {
                writeResult(out, active.get(i).getEndpointName(), LookupVerdict.FAILED);
            }
        }

        Map<String, Object> doneLine = LinkedHashMap.newLinkedHashMap(3);
        doneLine.put("type", "done");
        doneLine.put("total", active.size());
        doneLine.put("flagged", flagged);
        writeLine(out, doneLine);
    }

    /**
     * Resolves a single provider, converting any failure into a {@link LookupVerdict#FAILED} so one
     * bad provider never aborts the scan.
     *
     * @param provider The provider to resolve.
     * @param prepared The prepared URL.
     * @return The provider's verdict, or {@link LookupVerdict#FAILED} on error.
     */
    private @NonNull LookupVerdict safeResolve(@NonNull Provider provider,
                                               @NonNull PreparedUrl prepared) {
        try {
            return proxyHandler.resolveForCheck(provider, prepared);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] /check resolution failed: {}", provider.getDisplayName(), e.getClass().getName());
            return LookupVerdict.FAILED;
        }
    }

    /**
     * Writes a single provider result line.
     *
     * @param out The response output stream.
     * @param endpointName The provider endpoint name (the grid key).
     * @param verdict The resolved verdict.
     */
    private static void writeResult(@NonNull OutputStream out,
                                    @NonNull String endpointName,
                                    @NonNull LookupVerdict verdict) {
        Map<String, Object> line = LinkedHashMap.newLinkedHashMap(4);
        line.put("type", "result");
        line.put("provider", endpointName);
        line.put("result", verdict.primary().getValue());
        line.put("results", verdict.values());
        writeLine(out, line);
    }

    /**
     * Serializes one map as a JSON object followed by a newline and flushes it.
     *
     * @param out The response output stream.
     * @param line The object to serialize.
     */
    private static void writeLine(@NonNull OutputStream out, @NonNull Map<String, Object> line) {
        try {
            String json = JacksonUtil.MAPPER.writeValueAsString(line);
            out.write(json.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            // The client likely disconnected mid-stream; nothing more can be written
            log.debug("[check] Failed to write stream line: {}", e.getClass().getName());
        }
    }

    /**
     * Whether a verdict counts as a detection for the summary tally.
     *
     * @param verdict The verdict to test.
     * @return {@code true} if the verdict is neither allowed, failed, nor rate-limited.
     */
    private static boolean isFlagged(@NonNull LookupVerdict verdict) {
        return !verdict.isAllowedOnly() && !verdict.isFailed() && !verdict.isRateLimited();
    }

    /**
     * Verifies a Cloudflare Turnstile token. Fails closed on any error. Skipped when disabled.
     *
     * @param token The captcha token from the client.
     * @param request The incoming request, used for the optional remote IP hint.
     * @return {@code true} if verification passed or is disabled, {@code false} otherwise.
     */
    @SuppressWarnings("NestedMethodCall")
    private boolean verifyTurnstile(@Nullable String token, @NonNull HttpServletRequest request) {
        if (!turnstileEnabled) {
            return true;
        }

        if (turnstileSecret.isBlank() || token == null || token.isBlank() || token.length() > 2048) {
            return false;
        }

        try {
            StringBuilder form = new StringBuilder(256)
                    .append("secret=").append(URLEncoder.encode(turnstileSecret, StandardCharsets.UTF_8))
                    .append("&response=").append(URLEncoder.encode(token, StandardCharsets.UTF_8));

            String remoteIp = request.getHeader("X-Real-IP");

            if (remoteIp != null && !remoteIp.isBlank() && remoteIp.length() <= 45) {
                form.append("&remoteip=").append(URLEncoder.encode(remoteIp.strip(), StandardCharsets.UTF_8));
            }

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(turnstileVerifyUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                    .build();

            HttpResponse<String> response = turnstileClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                log.warn("[check] Turnstile verify returned HTTP {}", response.statusCode());
                return false;
            }

            Map<String, Object> parsed = JacksonUtil.MAPPER.readValue(response.body(), JacksonUtil.MAP_TYPE_OBJECT);
            return Boolean.TRUE.equals(parsed.get("success"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[check] Turnstile verification error: {}", e.getClass().getName());
            return false;
        }
    }

    /**
     * Parses, validates, and normalizes a URL into the three key forms the providers need.
     * <p>
     * The normalization mirrors the extension's own URL handling: a scheme is assumed when missing,
     * the host is lowercased and IDN-encoded with any leading {@code www.} removed, the path keeps no
     * trailing slash, and the query and fragment are dropped. Private, internal, and malformed hosts
     * are rejected.
     *
     * @param rawUrl The raw URL string from the request.
     * @return The prepared URL, or {@code null} if the input is not a valid public http(s) URL.
     */
    private static @Nullable PreparedUrl prepareUrl(@Nullable String rawUrl) {
        if (rawUrl == null) {
            return null;
        }

        String trimmed = rawUrl.strip();

        if (trimmed.isEmpty() || trimmed.length() > 8192) {
            return null;
        }

        // Assume https for schemeless input, matching common scanners and the extension
        if (!HTTPS_PATTERN.matcher(trimmed).matches()) {
            trimmed = "https://" + trimmed;
        }

        URI uri;

        try {
            uri = new URI(trimmed);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            return null;
        }

        String scheme = uri.getScheme();

        if (scheme == null) {
            return null;
        }

        scheme = scheme.toLowerCase(Locale.ROOT);

        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            return null;
        }

        String host = uri.getHost();

        if (host == null || host.isBlank()) {
            return null;
        }

        host = host.strip().toLowerCase(Locale.ROOT);

        // Strip surrounding brackets from IPv6 literals
        if (host.length() >= 2 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
            host = host.substring(1, host.length() - 1);
        }

        // Strip trailing dots and a single leading www., mirroring the extension's canonicalization
        while (!host.isEmpty() && host.charAt(host.length() - 1) == '.') {
            host = host.substring(0, host.length() - 1);
        }

        if (host.startsWith("www.")) {
            host = host.substring(4);
        }

        if (host.length() > 253 || !host.contains(".")) {
            return null;
        }

        // IDN-encode registrable hostnames; leave IP literals (which contain ':' or are dotted quads) alone
        if (host.indexOf(':') < 0) {
            try {
                host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }

        // Reject private, internal, and loopback hosts
        if (NetworkUtil.isPrivateHost(host)) {
            return null;
        }

        String path = uri.getRawPath();

        if (path == null) {
            path = "";
        }

        // Drop a trailing slash so the canonical form matches the extension's normalized URL
        while (path.length() > 1 && path.charAt(path.length() - 1) == '/') {
            path = path.substring(0, path.length() - 1);
        }

        if ("/".equals(path)) {
            path = "";
        }

        String canonicalUrl = "https://" + host + path;
        String bareHost = RequestUtil.getBareHost(host);
        boolean hasRegistrable = RequestUtil.hasRegistrableDomain(host);
        return new PreparedUrl(host, bareHost, canonicalUrl, hasRegistrable);
    }

    /**
     * Fetches a per-IP bucket, creating it from the given bandwidth on first use.
     *
     * @param cache The bucket cache.
     * @param key The hashed IP key.
     * @param bandwidth The bandwidth to build a new bucket from.
     * @return The bucket for this IP.
     */
    private static @NonNull Bucket bucket(@NonNull Cache<String, Bucket> cache,
                                          @NonNull String key,
                                          @NonNull Bandwidth bandwidth) {
        return cache.get(key, ignored -> Bucket.builder().addLimit(bandwidth).build());
    }

    /**
     * Retrieves a completed future's value, translating failures into {@code null}.
     *
     * @param future The completed future.
     * @return The value, or {@code null} on failure.
     */
    private static @Nullable IndexedVerdict safeGet(@NonNull Future<IndexedVerdict> future) {
        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            return null;
        }
    }
}
