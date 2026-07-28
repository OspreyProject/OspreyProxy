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

import org.jspecify.annotations.Nullable;

import java.util.Set;

/**
 * Represents a snapshot of the live, merged list content for a descriptor.
 * <p>
 * This holds only the merged domain set served to lookups. Conditional-fetch ETags are tracked
 * per source URL by {@code LocalListUtil} (a descriptor may aggregate several sources), so there
 * is no single ETag that meaningfully describes the merged snapshot.
 *
 * @param domainSet The set of domains in the snapshot, or null if not yet loaded.
 */
record ListSnapshot(@Nullable Set<String> domainSet) {

    static final ListSnapshot EMPTY = new ListSnapshot(null);
}
