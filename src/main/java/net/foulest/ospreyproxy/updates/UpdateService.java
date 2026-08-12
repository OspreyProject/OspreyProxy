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
package net.foulest.ospreyproxy.updates;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The self-hosted CRX update server's catalog: which builds exist and which build each channel offers.
 * <p>
 * The whole feature is off by default ({@code osprey.updates.enabled=false}) so the public deployment on
 * {@code api.osprey.ac} serves no updates. A self-hoster that wants to control which extension version
 * runs where turns it on and points {@code osprey.updates.path} at a directory holding two small
 * operator-authored files and the packaged CRX builds:
 * <ul>
 *   <li>{@code releases.json} lists every packaged build (version, CRX filename, notes, date). This file
 *       is append-mostly: publishing a build adds one entry.</li>
 *   <li>{@code channels.json} maps each channel (for example {@code stable} and {@code beta}) to the
 *       version it currently offers, or to {@code latest}. This is the knob an operator flips to stage a
 *       beta, pin a client to a known-good build, or roll back.</li>
 * </ul>
 * Both files are re-read automatically when either one's modification time changes, checked at most once
 * per second, so staging and rollbacks take effect within about a second without a restart. A read
 * failure keeps the last-known-good catalog in place rather than dropping to an empty one, mirroring the
 * fail-safe posture used elsewhere: a bad edit or a transient I/O error never turns into "no updates
 * offered" in a way that could surprise a fleet.
 * <p>
 * Because the version a browser installs must equal the version advertised in the manifest, the server
 * never invents or rewrites versions. It serves exactly what the operator packaged. It does compute the
 * real SHA-256 and byte size of each CRX on disk, caches them keyed by file identity, and exposes them
 * for manifest integrity and for the release feed.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "osprey.updates.enabled", havingValue = "true")
public class UpdateService {

    private static final String RELEASES_FILE = "releases.json";
    private static final String CHANNELS_FILE = "channels.json";
    private static final String SHA_256 = "SHA-256";

    // Do not stat the catalog files more than once per second, so a burst of update checks does not turn
    // into a syscall storm. Staging and rollback are human-timescale actions, so a one-second lag is fine.
    private static final long STAT_THROTTLE_NANOS = Duration.ofSeconds(1).toNanos();

    private final Path updatesDir;
    private final Path releasesPath;
    private final Path channelsPath;

    /**
     * The configured public origin used to build absolute {@code codebase} and download URLs, for example
     * {@code https://updates.example.com}. Blank means "derive it from the incoming request instead".
     */
    @Getter
    private final String baseUrl;

    // App id override from configuration; when blank the handler falls back to the id the browser asks for.
    private final String configuredAppId;

    // The current parsed catalog, replaced atomically on reload.
    private volatile UpdateCatalog catalog = UpdateCatalog.empty();

    // Computed CRX metadata (sha256 + size), cached by file identity so a repeat serve does not re-hash.
    private final Map<String, CRXMeta> crxMetaCache = new ConcurrentHashMap<>();

    // Catalog file freshness tracking, guarded by reloadLock for the actual reload.
    private final Object reloadLock = new Object();
    private volatile long releasesModifiedMillis = -1L;
    private volatile long channelsModifiedMillis = -1L;
    private volatile long lastStatNanos;

    /**
     * Binds update-server configuration. All values default so simply enabling the feature works with a
     * directory of files and no further properties.
     *
     * @param path Filesystem directory holding {@code releases.json}, {@code channels.json}, and the CRX builds.
     * @param baseUrl Public origin for building absolute URLs, or blank to derive from the request.
     * @param configuredAppId The extension application id to echo in manifests, or blank to echo the requested id.
     */
    public UpdateService(@Value("${osprey.updates.path:/var/lib/osprey/updates}") String path,
                         @Value("${osprey.updates.base-url:}") String baseUrl,
                         @Value("${osprey.updates.app-id:}") String configuredAppId) {
        updatesDir = Path.of(path.strip());
        releasesPath = updatesDir.resolve(RELEASES_FILE);
        channelsPath = updatesDir.resolve(CHANNELS_FILE);
        this.baseUrl = stripTrailingSlash(baseUrl.strip());
        this.configuredAppId = configuredAppId.strip();
    }

    /**
     * Loads the catalog once at startup so the first update check does not pay the parse cost and so a
     * misconfiguration is visible in the logs immediately rather than on first traffic.
     */
    @PostConstruct
    public void init() {
        reload();

        UpdateCatalog current = catalog;

        if (current.releases().isEmpty()) {
            log.warn("[updates] Update server enabled but no releases loaded from {}; "
                    + "update checks will offer nothing until releases.json is populated", releasesPath);
        } else {
            log.info("[updates] Loaded {} release(s) and {} channel(s) from {}",
                    current.releases().size(), current.channelPins().size(), updatesDir);
        }
    }

    /**
     * @return The current catalog snapshot, reloading first when the files on disk have changed.
     */
    public @NonNull UpdateCatalog catalog() {
        maybeReload();
        return catalog;
    }

    /**
     * Resolves the release a channel currently offers, reloading first when the files have changed.
     *
     * @param channel The channel name.
     * @return The resolved release, or {@code null} when the channel is unknown or its build is missing.
     */
    public @Nullable Release resolve(@Nullable String channel) {
        return catalog().resolve(channel);
    }

    /**
     * Resolves the effective application id for a manifest response: the configured id when set,
     * otherwise the id the browser presented in its update check.
     *
     * @param requestedAppId The application id parsed from the update-check query, or {@code null}.
     * @return The id to echo in the manifest, which may be empty when neither source supplies one.
     */
    public @NonNull String effectiveAppId(@Nullable String requestedAppId) {
        if (!configuredAppId.isEmpty()) {
            return configuredAppId;
        }
        return requestedAppId == null ? "" : requestedAppId;
    }

    /**
     * Reads a catalogued CRX from disk. The filename must belong to a release in the catalog, which is
     * confirmed by the caller, and must resolve to a regular file inside the updates directory.
     *
     * @param crx The CRX filename.
     * @return The absolute path to the file, or {@code null} when it is missing or escapes the directory.
     */
    public @Nullable Path crxPath(@NonNull String crx) {
        Path resolved = updatesDir.resolve(crx).normalize();

        // Reject anything that escapes the updates directory, defense in depth on top of the filename
        // validation the handler already applies.
        if (!resolved.startsWith(updatesDir)) {
            log.warn("[updates] Refusing CRX path outside updates directory: {}", crx);
            return null;
        }

        if (!Files.isRegularFile(resolved)) {
            return null;
        }
        return resolved;
    }

    /**
     * Returns the SHA-256 and byte size of a catalogued CRX, computing them once and caching by file
     * identity (path, size, and modification time) so a repeat serve does not re-hash an unchanged file.
     *
     * @param crx The CRX filename.
     * @return The metadata, or {@code null} when the file is missing or unreadable.
     */
    public @Nullable CRXMeta crxMeta(@NonNull String crx) {
        Path path = crxPath(crx);

        if (path == null) {
            return null;
        }

        long size;
        long modified;

        try {
            size = Files.size(path);
            modified = Files.getLastModifiedTime(path).toMillis();
        } catch (IOException e) {
            log.warn("[updates] Could not stat CRX {}: {}", crx, e.getClass().getName());
            return null;
        }

        CRXMeta cached = crxMetaCache.get(crx);

        if (cached != null && cached.size() == size && cached.modifiedMillis() == modified) {
            return cached;
        }

        String digest;

        try {
            digest = sha256Hex(Files.readAllBytes(path));
        } catch (IOException e) {
            log.warn("[updates] Could not hash CRX {}: {}", crx, e.getClass().getName());
            return null;
        }

        CRXMeta meta = new CRXMeta(digest, size, modified);
        crxMetaCache.put(crx, meta);
        return meta;
    }

    /**
     * Re-reads the catalog when either file is stale, throttling the modification-time check to at most
     * once per second so an update-check burst never turns into a stat storm.
     */
    private void maybeReload() {
        long now = System.nanoTime();

        if (now - lastStatNanos < STAT_THROTTLE_NANOS) {
            return;
        }

        lastStatNanos = now;
        long releasesModified = lastModified(releasesPath);
        long channelsModified = lastModified(channelsPath);

        if (releasesModified != releasesModifiedMillis || channelsModified != channelsModifiedMillis) {
            synchronized (reloadLock) {
                if (releasesModified != releasesModifiedMillis || channelsModified != channelsModifiedMillis) {
                    reload();
                }
            }
        }
    }

    /**
     * Reads and parses both catalog files and atomically replaces the in-memory catalog. On a read or
     * parse failure the previous catalog is kept in place, so a bad edit never drops the fleet to no
     * updates. Records the files' modification times so the next {@link #maybeReload()} is a no-op until
     * they change again.
     */
    private void reload() {
        Map<String, Object> releasesDoc = readJson(releasesPath);
        Map<String, Object> channelsDoc = readJson(channelsPath);

        // A missing releases file is a valid, if empty, state; a present-but-unparseable one keeps the
        // last-known-good catalog rather than blanking it.
        if (releasesDoc == null && Files.exists(releasesPath)) {
            log.warn("[updates] Keeping previous catalog; {} could not be read or parsed", releasesPath);
            releasesModifiedMillis = lastModified(releasesPath);
            channelsModifiedMillis = lastModified(channelsPath);
            return;
        }

        String appId = configuredAppId;
        List<Release> releases = new ArrayList<>();

        if (releasesDoc != null) {
            Object docAppId = releasesDoc.get("app_id");

            if (appId.isEmpty() && docAppId instanceof String s) {
                appId = s.strip();
            }

            releases = parseReleases(releasesDoc.get("releases"));
        }

        // Newest first, so a "latest" channel resolves to element zero.
        releases.sort((a, b) -> UpdateCatalog.compareVersions(b.version(), a.version()));

        Map<String, String> channelPins = parseChannels(channelsDoc);
        catalog = new UpdateCatalog(appId, releases, channelPins);

        releasesModifiedMillis = lastModified(releasesPath);
        channelsModifiedMillis = lastModified(channelsPath);
    }

    /**
     * Parses the {@code releases} array into {@link Release} records, skipping any entry that lacks a
     * version or a CRX filename.
     *
     * @param raw The value under the {@code releases} key.
     * @return The parsed releases in file order.
     */
    private static @NonNull List<Release> parseReleases(@Nullable Object raw) {
        List<Release> releases = new ArrayList<>();

        if (!(raw instanceof List<?> list)) {
            return releases;
        }

        for (Object element : list) {
            if (!(element instanceof Map<?, ?> map)) {
                continue;
            }

            String version = asString(map.get("version"));
            String crx = asString(map.get("crx"));

            if (version == null || version.isBlank() || crx == null || crx.isBlank()) {
                log.warn("[updates] Skipping release entry missing version or crx");
                continue;
            }

            releases.add(new Release(version.strip(), crx.strip(),
                    asString(map.get("date")),
                    asString(map.get("notes")),
                    asString(map.get("sha256")),
                    asString(map.get("min_browser_version")),
                    asString(map.get("rollback_of"))));
        }
        return releases;
    }

    /**
     * Parses the {@code channels} object into a channel-to-pin map with lowercased channel names. When
     * the file is missing or empty, a single {@code stable} channel tracking {@code latest} is assumed so
     * the server is useful out of the box.
     *
     * @param channelsDoc The parsed channels document, or {@code null}.
     * @return The channel-to-pin map.
     */
    private static @NonNull Map<String, String> parseChannels(@Nullable Map<String, Object> channelsDoc) {
        Map<String, String> pins = new HashMap<>();

        Object channels = channelsDoc == null ? null : channelsDoc.get("channels");

        if (channels instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String name = asString(entry.getKey());

                if (name == null || name.isBlank()) {
                    continue;
                }

                String pin = pinOf(entry.getValue());

                if (pin != null) {
                    pins.put(name.strip().toLowerCase(Locale.ROOT), pin);
                }
            }
        }

        if (pins.isEmpty()) {
            pins.put("stable", UpdateCatalog.LATEST);
        }
        return pins;
    }

    /**
     * Extracts a channel's pin from its config value, which may be a bare version string or an object
     * carrying a {@code version} field.
     *
     * @param value The channel's config value.
     * @return The pin string, or {@code null} when none can be read.
     */
    private static @Nullable String pinOf(@Nullable Object value) {
        if (value instanceof String s && !s.isBlank()) {
            return s.strip();
        }

        if (value instanceof Map<?, ?> map) {
            String version = asString(map.get("version"));
            return version == null || version.isBlank() ? null : version.strip();
        }
        return null;
    }

    /**
     * Reads and parses a JSON object file.
     *
     * @param path The file to read.
     * @return The parsed map, or {@code null} when the file is absent, unreadable, or not a JSON object.
     */
    private static @Nullable Map<String, Object> readJson(@NonNull Path path) {
        if (!Files.exists(path)) {
            return null;
        }

        try {
            byte[] bytes = Files.readAllBytes(path);
            return JacksonUtil.MAPPER.readValue(bytes, JacksonUtil.MAP_TYPE_OBJECT);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[updates] Failed to read {}: {}", path, e.getClass().getName());
            return null;
        }
    }

    /**
     * @param path The file to stat.
     * @return The file's modification time in epoch millis, or {@code -1} when it does not exist or cannot be read.
     */
    private static long lastModified(@NonNull Path path) {
        try {
            return Files.exists(path) ? Files.getLastModifiedTime(path).toMillis() : -1L;
        } catch (IOException e) {
            return -1L;
        }
    }

    /**
     * Coerces a JSON value to a trimmed string, or {@code null} when it is not a string.
     *
     * @param value The raw value.
     * @return The string value, or {@code null}.
     */
    private static @Nullable String asString(@Nullable Object value) {
        return value instanceof String s ? s : null;
    }

    /**
     * Removes a single trailing slash so URL building never produces a double slash.
     *
     * @param value The value to trim.
     * @return The value without a trailing slash.
     */
    private static @NonNull String stripTrailingSlash(@NonNull String value) {
        return !value.isEmpty() && value.charAt(value.length() - 1) == '/' ? value.substring(0, value.length() - 1) : value;
    }

    /**
     * Hashes bytes with SHA-256 and returns the lowercase hex digest.
     *
     * @param bytes The bytes to hash.
     * @return The hex-encoded SHA-256 digest.
     */
    private static @NonNull String sha256Hex(byte @NonNull [] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            return HexFormat.of().formatHex(digest.digest(bytes)).toLowerCase(Locale.ROOT);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw new IllegalStateException(SHA_256 + " not available", e);
        }
    }
}
