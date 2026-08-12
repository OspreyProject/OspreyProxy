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

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

/**
 * Service for recording and analyzing request metrics.
 */
@Service
@RequiredArgsConstructor
public class MetricsService {

    // Micrometer registry injected by Spring Boot autoconfiguration
    private final MeterRegistry registry;

    // Label value used for requests that carry no tenant (the anonymous public deployment)
    private static final String NO_TENANT = "anonymous";

    /**
     * Records a request for the given provider with no tenant dimension. Retained for callers that have
     * no tenant context; tags the request as {@code anonymous}.
     *
     * @param providerName The name of the provider handling the request,
     *                     used for tagging metrics and tracking per-provider stats.
     */
    public void recordRequest(@NonNull String providerName) {
        recordRequest(providerName, NO_TENANT);
    }

    /**
     * Records a request for the given provider and tenant. The tenant is an operator-controlled opaque
     * id (or {@code public}/{@code anonymous}), never end-user input, so its cardinality is bounded and
     * safe as a Prometheus label. This is what makes per-client usage visible in Prometheus.
     *
     * @param providerName The name of the provider handling the request.
     * @param tenant The resolved tenant id, or {@code public}/{@code anonymous} when there is none.
     */
    public void recordRequest(@NonNull String providerName, @NonNull String tenant) {
        registry.counter("osprey.requests.total",
                Tags.of("provider", providerName, "tenant", tenant)).increment();
    }

    /**
     * Records a cache hit, incrementing the appropriate counter in the registry. This method is called by
     * providers when they successfully serve a request from cache, allowing us to track cache effectiveness over time.
     */
    public void recordCacheHit() {
        registry.counter("osprey.cache.hits").increment();
    }

    /**
     * Records a cache miss, incrementing the appropriate counter in the registry. This method is called by
     * providers when they fail to serve a request from cache, allowing us to track cache effectiveness over time.
     */
    public void recordCacheMiss() {
        registry.counter("osprey.cache.misses").increment();
    }

    /**
     * Records a blocked request (any non-2xx response) for the given provider and HTTP status code with
     * no tenant dimension; tags it as {@code anonymous}.
     *
     * @param providerName The name of the provider that rejected the request.
     * @param statusCode   The HTTP status code returned to the client (e.g., 400, 429, 502).
     */
    public void recordBlocked(@NonNull String providerName, int statusCode) {
        recordBlocked(providerName, statusCode, NO_TENANT);
    }

    /**
     * Records a blocked request for the given provider, status, and tenant.
     * Tagged by provider, status, and tenant so Grafana can break down block reasons per client.
     *
     * @param providerName The name of the provider that rejected the request.
     * @param statusCode   The HTTP status code returned to the client (e.g., 400, 429, 502).
     * @param tenant       The resolved tenant id, or {@code public}/{@code anonymous} when there is none.
     */
    public void recordBlocked(@NonNull String providerName, int statusCode, @NonNull String tenant) {
        registry.counter("osprey.requests.blocked",
                Tags.of("provider", providerName, "status", String.valueOf(statusCode), "tenant", tenant)).increment();
    }

    /**
     * Records that the self-hosted update server offered a build to a browser on a channel. Both labels
     * are operator-controlled and bounded (a handful of channel names, a handful of live versions), so
     * they are safe as Prometheus labels. This makes staged rollouts visible: a query grouped by
     * {@code version} shows how a new build is spreading across a channel over time.
     *
     * @param channel The channel that served the offer (for example {@code stable} or {@code beta}).
     * @param version The extension version offered.
     */
    public void recordUpdateServed(@NonNull String channel, @NonNull String version) {
        registry.counter("osprey.updates.served",
                Tags.of("channel", channel, "version", version)).increment();
    }
}
