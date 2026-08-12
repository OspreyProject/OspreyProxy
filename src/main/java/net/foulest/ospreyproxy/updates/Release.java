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

/**
 * One packaged extension build in the update catalog.
 * <p>
 * A release is authored by the operator as an entry in {@code releases.json} and pairs a version with
 * the CRX file that carries it. The version here must match the version inside the packaged CRX's own
 * manifest, because Chromium refuses an update whose advertised version does not match the package it
 * downloads. Everything else is metadata surfaced through the machine-readable release feed for change
 * management.
 *
 * @param version The extension version this release carries, matching the CRX's internal manifest version.
 * @param crx The CRX filename inside the updates directory, for example {@code osprey-2.0.6.crx}.
 * @param date The release date as authored, ideally ISO-8601, or {@code null} when omitted.
 * @param notes A short human-readable changelog line, or {@code null} when omitted.
 * @param sha256 An operator-declared SHA-256 of the CRX, or {@code null}. The server always computes and
 *               serves the real digest of the file on disk; this field is only a convenience for the feed.
 * @param minBrowserVersion A minimum browser version this build requires ({@code prodversionmin}), or {@code null}.
 * @param rollbackOf The version this build reverts, for provenance in the feed, or {@code null} when it is not a rollback.
 */
public record Release(@NonNull String version,
                      @NonNull String crx,
                      @Nullable String date,
                      @Nullable String notes,
                      @Nullable String sha256,
                      @Nullable String minBrowserVersion,
                      @Nullable String rollbackOf) {

}
