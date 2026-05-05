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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.jspecify.annotations.NonNull;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Utility class for resolving hostnames using Cloudflare's DNS-over-HTTPS (DoH) API.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class ResolveUtil {

    // HTTP/2 client for DoH queries.
    // 2s connect, 2s connection-request, 5s response, 10s operation timeout.
    private static final CloseableHttpClient DOH_CLIENT =
            HttpClientFactory.createHttp2Client(2, 2, 5, 10);

    // Cloudflare's DoH JSON endpoint
    private static final String DOH_URL = "https://cloudflare-dns.com/dns-query";

    // Separate caches per result so each can have its own TTL.
    // Positive results (host.doesHostResolve) cached for 5 minutes; negative for 1 minute.
    private static final Cache<String, Boolean> POSITIVE_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(5))
            .maximumSize(50_000)
            .build();
    private static final Cache<String, Boolean> NEGATIVE_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(1))
            .maximumSize(50_000)
            .build();

    /**
     * Checks if the hostname is resolvable via Cloudflare's DoH.
     *
     * @param host The hostname to resolve.
     * @return {@code true} if the host can resolve or the lookup could not be completed (fail-open),
     *         {@code false} only if Cloudflare returned no answer records.
     */
    @SuppressWarnings("NestedMethodCall")
    static boolean doesHostResolve(@NonNull String host) {
        if (Boolean.TRUE.equals(POSITIVE_CACHE.getIfPresent(host))) {
            return true;
        }

        if (Boolean.TRUE.equals(NEGATIVE_CACHE.getIfPresent(host))) {
            return false;
        }

        boolean result = doesQueryHaveAnswers(host);

        if (result) {
            POSITIVE_CACHE.put(host, Boolean.TRUE);
        } else {
            NEGATIVE_CACHE.put(host, Boolean.TRUE);
        }
        return result;
    }

    /**
     * Queries Cloudflare's DoH API for the given {@code host}.
     * <p>
     * A host is considered to have records only when {@code Status == 0} AND
     * the {@code Answer} array is present and non-empty.
     *
     * @param host The hostname to query.
     * @return {@code true} if the host has answer records; {@code false} if Status is non-zero,
     *         the Answer array is absent/empty, or the response could not be parsed.
     *         Fail-open on I/O errors.
     */
    @SuppressWarnings("NestedMethodCall")
    private static boolean doesQueryHaveAnswers(@NonNull String host) {
        try {
            String encodedHost = URLEncoder.encode(host, StandardCharsets.UTF_8);
            String url = DOH_URL + "?name=" + encodedHost;

            ClassicHttpRequest request = new HttpGet(url);
            request.addHeader("Accept", "application/dns-json");

            return DOH_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.warn("DoH query returned HTTP {}", statusCode);
                    return true;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity, 64 << 10);

                if (body == null || body.length == 0) {
                    log.warn("DoH query returned empty body");
                    return true;
                }

                Map<String, Object> data;

                try {
                    data = JacksonUtil.MAPPER.readValue(body, JacksonUtil.MAP_TYPE_OBJECT);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.warn("DoH query returned unparseable body ({})", e.getClass().getName());
                    return true;
                }

                Object statusObj = data.get("Status");
                Object answerObj = data.get("Answer");

                if (!(statusObj instanceof Number)) {
                    log.warn("DoH query returned invalid Status field");
                    return true;
                }

                int dnsStatus = ((Number) statusObj).intValue();
                boolean hasAnswers = answerObj instanceof List<?> && !((Collection<?>) answerObj).isEmpty();
                return dnsStatus == 0 && hasAnswers;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("DoH query failed ({})", e.getClass().getName());
            return true;
        }
    }
}
