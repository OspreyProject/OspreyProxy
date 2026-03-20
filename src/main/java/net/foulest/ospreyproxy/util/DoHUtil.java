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
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Utility class for performing DNS-over-HTTPS (DoH) queries to Cloudflare's DoH API.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DoHUtil {

    // HTTP/2 client for DoH queries
    // Multiplexing handles max conn. total and max conn. per route
    // 2s connect timeout, 2s connection request timeout, 5s response timeout, 10s operation timeout
    private static final CloseableHttpClient DOH_CLIENT;

    static {
        CloseableHttpAsyncClient asyncClient = HttpAsyncClients.customHttp2()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(2))
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(2))
                        .setResponseTimeout(Timeout.ofSeconds(5))
                        .build())
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .build();

        asyncClient.start();
        DOH_CLIENT = HttpAsyncClients.classic(asyncClient, Timeout.ofSeconds(10));
    }

    // Cloudflare's DoH JSON endpoint
    private static final String DOH_URL = "https://cloudflare-dns.com/dns-query";

    // Cache TTLs
    private static final Duration POSITIVE_TTL = Duration.ofMinutes(5);
    private static final Duration NEGATIVE_TTL = Duration.ofMinutes(1);

    // Separate caches so each has its own TTL
    private static final Cache<String, Boolean> POSITIVE_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(POSITIVE_TTL)
            .maximumSize(50_000)
            .build();
    private static final Cache<String, Boolean> NEGATIVE_CACHE = Caffeine.newBuilder()
            .expireAfterWrite(NEGATIVE_TTL)
            .maximumSize(50_000)
            .build();

    /**
     * Checks if the hostname is resolvable via Cloudflare's DoH.
     *
     * @param host The hostname to resolve.
     * @return {@code true} if the host exists or the check could not be completed,
     *         {@code false} only if Cloudflare returned no answer records.
     */
    @SuppressWarnings("NestedMethodCall")
    public static boolean hostExists(@NonNull String host) {
        // Cache hit: previously confirmed to exist
        if (Boolean.TRUE.equals(POSITIVE_CACHE.getIfPresent(host))) {
            return true;
        }

        // Cache hit: previously confirmed as non-existent
        if (Boolean.TRUE.equals(NEGATIVE_CACHE.getIfPresent(host))) {
            return false;
        }

        boolean queryResult = queryHasAnswers(host);

        if (queryResult) {
            POSITIVE_CACHE.put(host, Boolean.TRUE);
            return true;
        }

        NEGATIVE_CACHE.put(host, Boolean.TRUE);
        return false;
    }

    /**
     * Queries Cloudflare's DoH API for the given {@code host}.
     * <p>
     * A host is considered to have records only when {@code Status == 0} AND
     * the {@code Answer} array is present and non-empty. Mirrors
     * {@code Status === 0 && Answer && Answer.length > 0} in the browser extension.
     *
     * @param host The hostname to query.
     * @return {@code true} if the host has answer records,
     *         {@code false} if Status is non-zero, the Answer array is absent/empty,
     *         or the response could not be parsed. Fail-open on I/O errors.
     */
    private static boolean queryHasAnswers(@NonNull String host) {
        try {
            String encodedHost = URLEncoder.encode(host, StandardCharsets.UTF_8);
            String url = DOH_URL + "?name=" + encodedHost;

            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", "application/dns-json");

            return DOH_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.error("DoH query for {} returned HTTP {}", host, statusCode);
                    return true;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity, 64 * 1024);

                if (body == null || body.length == 0) {
                    log.error("DoH query for {} returned empty body", host);
                    return true;
                }

                Map<String, Object> data;

                try {
                    data = JacksonUtil.MAPPER.readValue(body, JacksonUtil.MAP_TYPE_OBJECT);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.error("DoH query for {} returned unparseable body ({})", host, e.getClass().getName());
                    return true;
                }

                Object statusObj = data.get("Status");
                Object answerObj = data.get("Answer");

                if (!(statusObj instanceof Number)) {
                    log.error("DoH query for {} returned invalid Status field", host);
                    return true;
                }

                int dnsStatus = ((Number) statusObj).intValue();
                boolean hasAnswers = answerObj instanceof List<?> && !((Collection<?>) answerObj).isEmpty();
                return dnsStatus == 0 && hasAnswers;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("DoH query for {} failed ({})", host, e.getClass().getName());
            return true;
        }
    }
}
