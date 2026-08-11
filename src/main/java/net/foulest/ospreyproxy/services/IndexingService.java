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
package net.foulest.ospreyproxy.services;

import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.store.ScanRecord;
import net.foulest.ospreyproxy.store.ScanStore;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Periodically announces newly hard-flagged URLs to IndexNow-participating search engines.
 * <p>
 * This is the server-side half of publishing. It runs on a timer, asks the store for indexable
 * records that have not been announced yet, submits their crawlable page URLs to IndexNow in one
 * batch, and marks them announced so they are not resubmitted. It does not build any HTML; the
 * static site build creates the actual pages and the sitemap. IndexNow simply nudges the engines
 * that honor it to come and crawl the fresh pages sooner.
 * <p>
 * The whole service is inert unless the store is enabled and both an IndexNow key and a submission
 * endpoint are configured. The key must match the key file already hosted on the site.
 */
@Slf4j
@Service
@ConditionalOnBean(ScanStore.class)
public class IndexingService {

    private static final String HOST = "osprey.ac";

    private final ScanStore store;
    private final String key;
    private final String keyLocation;
    private final String submitUrl;
    private final int batchLimit;
    private final HttpClient client;

    /**
     * Constructs the indexing service.
     *
     * @param store The durable scan store.
     * @param key The IndexNow key, matching the key file hosted on the site.
     * @param keyLocation The public URL of the hosted key file.
     * @param submitUrl The IndexNow submission endpoint.
     * @param batchLimit The maximum number of URLs to submit per run.
     * @param timeoutSeconds The submission request timeout, in seconds.
     */
    public IndexingService(@NonNull ScanStore store,
                           @Value("${osprey.indexnow.key:}") String key,
                           @Value("${osprey.indexnow.key-location:}") String keyLocation,
                           @Value("${osprey.indexnow.submit-url:https://api.indexnow.org/indexnow}") String submitUrl,
                           @Value("${osprey.indexnow.batch-limit:10000}") int batchLimit,
                           @Value("${osprey.indexnow.timeout-seconds:10}") long timeoutSeconds) {
        this.store = store;
        this.key = key;

        // Default the key file location to the site-hosted key when not set explicitly.
        this.keyLocation = keyLocation.isBlank() ? ("https://" + HOST + "/" + key + ".txt") : keyLocation;
        this.submitUrl = submitUrl;
        this.batchLimit = batchLimit;

        client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(timeoutSeconds))
                .build();
    }

    /**
     * Submits any newly indexable URLs to IndexNow, then marks them announced. Runs on a fixed delay
     * after the previous run finishes.
     */
    @Scheduled(initialDelayString = "${osprey.indexnow.initial-delay-millis:120000}", fixedDelayString = "${osprey.indexnow.interval-millis:2700000}")
    public void publish() {
        if (key.isBlank()) {
            return;
        }

        List<ScanRecord> pending = store.findUnpublished(batchLimit);

        if (pending.isEmpty()) {
            return;
        }

        List<String> pageUrls = new ArrayList<>(pending.size());
        List<String> canonicalUrls = new ArrayList<>(pending.size());

        for (ScanRecord scanRecord : pending) {
            pageUrls.add(scanRecord.pageUrl());
            canonicalUrls.add(scanRecord.canonicalUrl());
        }

        if (submit(pageUrls)) {
            store.markPublished(canonicalUrls, System.currentTimeMillis());
            log.info("[indexing] Announced {} URL(s) to IndexNow", pageUrls.size());
        }
    }

    /**
     * Submits a batch of URLs to IndexNow.
     *
     * @param urls The page URLs to submit.
     * @return {@code true} if the submission was accepted, {@code false} otherwise.
     */
    private boolean submit(@NonNull List<String> urls) {
        try {
            Map<String, Object> payload = LinkedHashMap.newLinkedHashMap(4);
            payload.put("host", HOST);
            payload.put("key", key);
            payload.put("keyLocation", keyLocation);
            payload.put("urlList", urls);

            String body = JacksonUtil.MAPPER.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(submitUrl))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            int code = response.statusCode();

            // IndexNow returns 200 on accept and 202 when queued for validation; both are successes
            if (code == 200 || code == 202) {
                return true;
            }

            log.warn("[indexing] IndexNow submission returned HTTP {}", code);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[indexing] IndexNow submission failed: {}", e.getClass().getName());
            return false;
        }
    }
}
