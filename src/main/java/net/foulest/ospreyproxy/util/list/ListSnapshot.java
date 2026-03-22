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
package net.foulest.ospreyproxy.util.list;

import org.jspecify.annotations.Nullable;

import java.util.Set;

/**
 * Represents a snapshot of a list, containing the live set of domains and the raw content string.
 */
final class ListSnapshot {

    /**
     * The live set of domains from the last successful fetch.
     */
    volatile @Nullable Set<String> domainSet;

    /**
     * The raw content string from the last successful fetch, used for hash verification and debugging.
     */
    volatile @Nullable String rawContent;

    ListSnapshot() {
        domainSet = null;
        rawContent = null;
    }
}
