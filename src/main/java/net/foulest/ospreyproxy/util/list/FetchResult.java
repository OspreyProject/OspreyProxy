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
package net.foulest.ospreyproxy.util.list;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Set;

/**
 * Represents the result of fetching content from a provider.
 *
 * @param domainSet The set of domains fetched from the provider, which may be empty.
 * @param etag The ETag associated with the fetched content, if available.
 * @param lastModified The Last-Modified value associated with the fetched content, if available.
 *                     Used as an If-Modified-Since fallback for sources that don't send an ETag.
 */
record FetchResult(@NonNull Set<String> domainSet, @Nullable String etag, @Nullable String lastModified) {

}
