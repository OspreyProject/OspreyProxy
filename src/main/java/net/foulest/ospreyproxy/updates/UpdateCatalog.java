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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * An immutable snapshot of the parsed update catalog: the packaged releases and the per-channel pins
 * that decide which release each channel currently offers.
 * <p>
 * A channel pin is either an exact version, which holds a client on a known-good build regardless of
 * what newer builds exist, or the literal {@code latest}, which tracks the highest version present. A
 * beta channel is nothing more than a second channel an operator points a subset of endpoints at, and a
 * rollback is expressed by pinning a channel back to an earlier build (see {@code docs/updates.md} for
 * the Chromium downgrade caveat that shapes how rollbacks are actually published).
 * <p>
 * The whole snapshot is replaced atomically by {@link UpdateService} on reload, so a reader either sees
 * the entire previous catalog or the entire new one, never a half-applied edit.
 *
 * @param appId The extension application id echoed in update manifests, or empty when unset.
 * @param releases The releases, already sorted newest first by version.
 * @param channelPins Channel name to pin ({@link #LATEST} or an exact version), keys lowercased.
 */
public record UpdateCatalog(String appId, List<Release> releases, Map<String, String> channelPins) {

    /**
     * The channel pin value that tracks the highest available version rather than a fixed one.
     */
    public static final String LATEST = "latest";

    /**
     * @return An empty catalog with no releases and no channels.
     */
    public static @NonNull UpdateCatalog empty() {
        return new UpdateCatalog("", List.of(), Map.of());
    }

    /**
     * @return The configured application id, or an empty string when none is set.
     */
    @Override
    public @NonNull String appId() {
        return appId;
    }

    /**
     * @return The releases, newest first.
     */
    @Override
    public @NonNull List<Release> releases() {
        return releases;
    }

    /**
     * @return The channel-to-pin map, channel names lowercased.
     */
    @Override
    public @NonNull Map<String, String> channelPins() {
        return channelPins;
    }

    /**
     * Resolves the release a channel currently offers.
     *
     * @param channel The channel name, matched case-insensitively.
     * @return The resolved release, or {@code null} when the channel is unknown or its pinned version is
     *         not present in the catalog.
     */
    public @Nullable Release resolve(@Nullable String channel) {
        if (channel == null || channel.isBlank()) {
            return null;
        }

        String pin = channelPins.get(channel.toLowerCase(Locale.ROOT));

        if (pin == null) {
            return null;
        }

        if (pin.equalsIgnoreCase(LATEST)) {
            return releases.isEmpty() ? null : releases.getFirst();
        }
        return byVersion(pin);
    }

    /**
     * Finds a release by its exact version.
     *
     * @param version The version to look up.
     * @return The matching release, or {@code null} when none matches.
     */
    private @Nullable Release byVersion(@Nullable String version) {
        if (version == null) {
            return null;
        }

        for (Release release : releases) {
            if (release.version().equals(version)) {
                return release;
            }
        }
        return null;
    }

    /**
     * Finds a release by its CRX filename. Used to confirm a download request targets a catalogued file
     * rather than an arbitrary path.
     *
     * @param crx The CRX filename to look up.
     * @return The matching release, or {@code null} when no release references that file.
     */
    public @Nullable Release byCrx(@Nullable String crx) {
        if (crx == null) {
            return null;
        }

        for (Release release : releases) {
            if (release.crx().equals(crx)) {
                return release;
            }
        }
        return null;
    }

    /**
     * Compares two dot-separated version strings numerically, segment by segment, so {@code 2.0.10}
     * sorts above {@code 2.0.9}. A missing trailing segment is treated as zero, and a non-numeric
     * segment falls back to a lexical comparison so malformed input still orders deterministically.
     *
     * @param a The first version.
     * @param b The second version.
     * @return A negative, zero, or positive result when {@code a} is lower than, equal to, or higher than {@code b}.
     */
    public static int compareVersions(@NonNull String a, @NonNull String b) {
        String[] left = a.split("\\.");
        String[] right = b.split("\\.");
        int max = Math.max(left.length, right.length);

        for (int i = 0; i < max; i++) {
            String ls = i < left.length ? left[i] : "0";
            String rs = i < right.length ? right[i] : "0";

            Long ln = parseSegment(ls);
            Long rn = parseSegment(rs);

            int cmp;

            if (ln != null && rn != null) {
                cmp = Long.compare(ln, rn);
            } else {
                cmp = ls.compareTo(rs);
            }

            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    /**
     * Parses one version segment as a non-negative long, or {@code null} when it is not numeric.
     *
     * @param segment The segment text.
     * @return The parsed value, or {@code null} when non-numeric.
     */
    private static @Nullable Long parseSegment(@NonNull String segment) {
        try {
            long value = Long.parseLong(segment);
            return value < 0 ? null : value;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
