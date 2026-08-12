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

import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.security.SecurityFilter;
import net.foulest.ospreyproxy.tenant.RateSettings;
import net.foulest.ospreyproxy.tenant.Tenant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

/**
 * Per-tenant identity and quota for self-hosted, multi-tenant deployments.
 * <p>
 * The public deployment on {@code api.osprey.ac} serves the extension anonymously, so this whole
 * feature is off by default ({@code osprey.tenant.auth.enabled=false}) and the extension-facing
 * {@code POST /{providerName}} endpoints behave exactly as they did before. A self-hoster that serves
 * several client organizations turns it on: every extension-facing request must then carry a per-tenant
 * API key in the configured header. {@code /check} and {@code /result} keep their existing public
 * protection and never require a tenant key.
 * <p>
 * The key store is a plain properties file kept outside the repository (mode {@code 0600}), pointed to
 * by {@code osprey.tenant.store.path}. Keys are never held in plaintext beyond parsing: each key is
 * hashed with SHA-256 and only the hash is retained, so a presented key is matched by hashing it and
 * looking the hash up. The file is re-read automatically when its modification time changes, so an
 * operator can rotate keys without restarting the process. Each tenant may list several keys at once,
 * which is what makes a zero-downtime rotation possible (add the new key, roll it to endpoints, then
 * drop the old one).
 * <p>
 * Each tenant also carries its own aggregate rate budget, built from the tenant's own settings in the
 * store or from the {@code osprey.tenant.rate.*} defaults. This budget is keyed by tenant alone, across
 * every endpoint and IP, so one client's traffic can never drain another client's allowance. It sits on
 * top of the existing per-{@code (provider, IP)} buckets, which the proxy additionally namespaces by
 * tenant so the two layers cannot leak into each other either.
 */
@Slf4j
@Service
public class TenantService {

    /**
     * Request attribute the {@link SecurityFilter} sets to the resolved tenant id once a request has
     * authenticated, so the downstream handler can namespace rate limits and label metrics by tenant.
     */
    public static final String TENANT_ATTRIBUTE = "osprey.tenant";

    /**
     * Tenant label used when tenant authentication is disabled (the public, anonymous deployment).
     */
    public static final String ANONYMOUS = "anonymous";

    /**
     * Tenant label used for the public {@code /check} aggregator, which has no tenant.
     */
    public static final String PUBLIC = "public";

    private static final String SHA_256 = "SHA-256";
    private static final String TENANT_PREFIX = "tenant.";

    // Do not stat the store file more than once per second, so a request burst does not turn into a
    // syscall storm. Key rotation is a human-timescale action, so a one-second reload lag is fine.
    private static final long STAT_THROTTLE_NANOS = Duration.ofSeconds(1).toNanos();

    @Getter
    private final boolean enabled;
    private final String headerName;
    private final @Nullable Path storePath;

    // Default per-tenant aggregate budget, applied to any tenant that does not override it in the store
    private final long defaultBurstCapacity;
    private final long defaultBurstWindowSeconds;
    private final long defaultSustainedCapacity;
    private final long defaultSustainedWindowSeconds;

    // Hashed-key -> tenant id, and tenant id -> tenant. Replaced atomically on reload.
    private volatile Map<String, String> keyHashToTenantId = Map.of();
    private volatile Map<String, Tenant> tenantsById = Map.of();

    // Store file freshness tracking, guarded by reloadLock for the actual reload
    private final Object reloadLock = new Object();
    private volatile long lastModifiedMillis = -1L;
    private volatile long lastStatNanos;

    /**
     * Binds tenant configuration. All values default so the public deployment needs no new properties.
     *
     * @param enabled Whether per-tenant authentication is enforced on extension-facing endpoints.
     * @param headerName The request header carrying the tenant key.
     * @param storePathValue Filesystem path to the tenant key store, or blank to configure none.
     * @param defaultBurstCapacity Default per-tenant burst token capacity.
     * @param defaultBurstWindowSeconds Default per-tenant burst refill window, in seconds.
     * @param defaultSustainedCapacity Default per-tenant sustained token capacity.
     * @param defaultSustainedWindowSeconds Default per-tenant sustained refill window, in seconds.
     */
    public TenantService(@Value("${osprey.tenant.auth.enabled:false}") boolean enabled,
                         @Value("${osprey.tenant.auth.header:X-Osprey-Tenant-Key}") String headerName,
                         @Value("${osprey.tenant.store.path:}") String storePathValue,
                         @Value("${osprey.tenant.rate.burst-capacity:11}") long defaultBurstCapacity,
                         @Value("${osprey.tenant.rate.burst-window-seconds:1}") long defaultBurstWindowSeconds,
                         @Value("${osprey.tenant.rate.sustained-capacity:400}") long defaultSustainedCapacity,
                         @Value("${osprey.tenant.rate.sustained-window-seconds:60}") long defaultSustainedWindowSeconds) {
        this.enabled = enabled;
        this.headerName = headerName;
        storePath = storePathValue.isBlank() ? null : Path.of(storePathValue.strip());
        this.defaultBurstCapacity = defaultBurstCapacity;
        this.defaultBurstWindowSeconds = defaultBurstWindowSeconds;
        this.defaultSustainedCapacity = defaultSustainedCapacity;
        this.defaultSustainedWindowSeconds = defaultSustainedWindowSeconds;
    }

    /**
     * Loads the store once at startup so the first request does not pay the parse cost, and so a
     * misconfiguration is visible in the logs immediately rather than on first traffic.
     */
    @PostConstruct
    public void init() {
        if (!enabled) {
            log.info("[tenant] Tenant authentication disabled; extension endpoints serve anonymously");
            return;
        }

        if (storePath == null) {
            log.warn("[tenant] Tenant authentication is enabled but no store path is set; "
                    + "every extension request will be rejected. Set osprey.tenant.store.path.");
            return;
        }

        reload();

        int count = tenantsById.size();

        if (count == 0) {
            log.warn("[tenant] Tenant authentication is enabled but no tenants loaded from {}; "
                    + "every extension request will be rejected until keys are added", storePath);
        } else {
            log.info("[tenant] Loaded {} tenant(s) from {}", count, storePath);
        }
    }

    /**
     * @return The request header name the tenant key is read from.
     */
    public @NonNull String getHeaderName() {
        return headerName;
    }

    /**
     * Resolves a presented key to its tenant, reloading the store first if the file changed.
     *
     * @param presentedKey The raw key value from the request header, possibly {@code null} or blank.
     * @return The matching tenant, or {@code null} if the key is missing, blank, or unknown.
     */
    public @Nullable Tenant resolve(@Nullable String presentedKey) {
        if (presentedKey == null || presentedKey.isBlank()) {
            return null;
        }

        maybeReload();

        String hash = sha256Hex(presentedKey.strip());
        String tenantId = keyHashToTenantId.get(hash);
        return tenantId == null ? null : tenantsById.get(tenantId);
    }

    /**
     * Reads the tenant id a request authenticated as, falling back to {@link #ANONYMOUS} when the
     * filter set nothing (tenant authentication is disabled).
     *
     * @param request The incoming request.
     * @return The resolved tenant id, or {@link #ANONYMOUS} when none was set.
     */
    public static @NonNull String tenantOf(@NonNull ServletRequest request) {
        Object value = request.getAttribute(TENANT_ATTRIBUTE);
        return value instanceof String tenantId && !tenantId.isEmpty() ? tenantId : ANONYMOUS;
    }

    /**
     * Re-reads the store when it is stale, throttling the modification-time check to at most once per
     * second so a request burst never turns into a stat storm.
     */
    private void maybeReload() {
        if (storePath == null) {
            return;
        }

        long now = System.nanoTime();

        if (now - lastStatNanos < STAT_THROTTLE_NANOS) {
            return;
        }

        lastStatNanos = now;
        long modified;

        try {
            modified = Files.getLastModifiedTime(storePath).toMillis();
        } catch (IOException e) {
            // A transient stat failure keeps the last-known-good tenant set in place rather than
            // dropping every tenant, mirroring the store's fail-safe posture elsewhere.
            log.warn("[tenant] Could not stat tenant store {}: {}", storePath, e.getClass().getName());
            return;
        }

        if (modified != lastModifiedMillis) {
            synchronized (reloadLock) {
                if (modified != lastModifiedMillis) {
                    reload();
                }
            }
        }
    }

    /**
     * Reads and parses the store file, atomically replacing the in-memory tenant maps. Tenants whose
     * rate settings are unchanged keep their existing budget buckets, so an unrelated edit (or a key
     * rotation) does not silently reset every tenant's allowance.
     */
    private void reload() {
        if (storePath == null) {
            return;
        }

        Properties properties = new Properties();

        try (InputStream in = Files.newInputStream(storePath)) {
            properties.load(in);
        } catch (IOException e) {
            log.warn("[tenant] Failed to read tenant store {}: {}", storePath, e.getClass().getName());
            return;
        }

        Map<String, String> parsedKeys = new HashMap<>();
        Map<String, RateSettings> parsedRates = new HashMap<>();

        for (String name : properties.stringPropertyNames()) {
            if (!name.startsWith(TENANT_PREFIX)) {
                continue;
            }

            String remainder = name.substring(TENANT_PREFIX.length());
            int dot = remainder.indexOf('.');

            if (dot <= 0) {
                continue;
            }

            String tenantId = remainder.substring(0, dot);
            String field = remainder.substring(dot + 1);
            String value = properties.getProperty(name, "").strip();
            parseTenantField(tenantId, field, value, parsedKeys, parsedRates);
        }

        applyParsed(parsedKeys, parsedRates);

        try {
            lastModifiedMillis = Files.getLastModifiedTime(storePath).toMillis();
        } catch (IOException e) {
            log.debug("[tenant] Could not record tenant store mtime: {}", e.getClass().getName());
        }
    }

    /**
     * Applies one {@code tenant.<id>.<field>} entry into the working key and rate maps.
     *
     * @param tenantId The tenant id parsed from the property name.
     * @param field The field after the tenant id (for example {@code keys} or {@code rate.burst-capacity}).
     * @param value The property value.
     * @param parsedKeys Accumulator mapping each key hash to its tenant id.
     * @param parsedRates Accumulator mapping each tenant id to its rate settings.
     */
    private void parseTenantField(@NonNull String tenantId,
                                  @NonNull String field,
                                  @NonNull String value,
                                  @NonNull Map<String, String> parsedKeys,
                                  @NonNull Map<String, RateSettings> parsedRates) {
        RateSettings rate = parsedRates.computeIfAbsent(tenantId, ignored -> defaultRateSettings());

        switch (field) {
            case "keys" -> {
                for (String rawKey : value.split(",")) {
                    String key = rawKey.strip();

                    if (key.isEmpty()) {
                        continue;
                    }

                    String hash = sha256Hex(key);
                    String previous = parsedKeys.putIfAbsent(hash, tenantId);

                    if (previous != null && !previous.equals(tenantId)) {
                        log.warn("[tenant] Key collision between tenants '{}' and '{}'; ignoring the later one",
                                previous, tenantId);
                    }
                }
            }

            case "rate.burst-capacity" ->
                    parsedRates.put(tenantId, rate.withBurstCapacity(parseLong(value, rate.burstCapacity())));

            case "rate.burst-window-seconds" ->
                    parsedRates.put(tenantId, rate.withBurstWindowSeconds(parseLong(value, rate.burstWindowSeconds())));

            case "rate.sustained-capacity" ->
                    parsedRates.put(tenantId, rate.withSustainedCapacity(parseLong(value, rate.sustainedCapacity())));

            case "rate.sustained-window-seconds" ->
                    parsedRates.put(tenantId, rate.withSustainedWindowSeconds(parseLong(value, rate.sustainedWindowSeconds())));

            default -> log.debug("[tenant] Ignoring unknown tenant field '{}' for tenant '{}'", field, tenantId);
        }
    }

    /**
     * Builds the immutable tenant maps from parsed input and swaps them in, reusing existing budget
     * buckets for any tenant whose rate settings are unchanged.
     *
     * @param parsedKeys Mapping of each key hash to its tenant id.
     * @param parsedRates Mapping of each tenant id to its rate settings.
     */
    private void applyParsed(@NonNull Map<String, String> parsedKeys,
                             @NonNull Map<String, RateSettings> parsedRates) {
        Map<String, Tenant> existing = tenantsById;
        Map<String, Tenant> rebuilt = HashMap.newHashMap(parsedRates.size());

        for (Map.Entry<String, RateSettings> entry : parsedRates.entrySet()) {
            String tenantId = entry.getKey();
            RateSettings rate = entry.getValue();
            Tenant previous = existing.get(tenantId);

            // Carry over the live buckets when nothing about the budget changed, so an edit that only
            // touches keys does not reset the tenant's in-flight allowance.
            if (previous != null && previous.rate.equals(rate)) {
                rebuilt.put(tenantId, previous);
            } else {
                rebuilt.put(tenantId, new Tenant(tenantId, rate));
            }
        }

        // Drop any hashed key whose tenant no longer exists, so a removed tenant cannot authenticate.
        Map<String, String> keys = HashMap.newHashMap(parsedKeys.size());

        for (Map.Entry<String, String> entry : parsedKeys.entrySet()) {
            if (rebuilt.containsKey(entry.getValue())) {
                keys.put(entry.getKey(), entry.getValue());
            }
        }

        tenantsById = Map.copyOf(rebuilt);
        keyHashToTenantId = Map.copyOf(keys);
    }

    /**
     * @return A {@link RateSettings} built from the configured defaults.
     */
    private @NonNull RateSettings defaultRateSettings() {
        return new RateSettings(defaultBurstCapacity, defaultBurstWindowSeconds,
                defaultSustainedCapacity, defaultSustainedWindowSeconds);
    }

    /**
     * Parses a positive {@code long}, falling back to a default on any malformed or non-positive value.
     *
     * @param value The raw string value.
     * @param fallback The value to use when parsing fails or the result is not positive.
     * @return The parsed value, or {@code fallback}.
     */
    private static long parseLong(@NonNull String value, long fallback) {
        try {
            long parsed = Long.parseLong(value.strip());
            return parsed > 0 ? parsed : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /**
     * Hashes a key with SHA-256 and returns the lowercase hex digest.
     *
     * @param value The key to hash.
     * @return The hex-encoded SHA-256 digest.
     */
    private static @NonNull String sha256Hex(@NonNull String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).toLowerCase(Locale.ROOT);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw new IllegalStateException(SHA_256 + " not available", e);
        }
    }
}
