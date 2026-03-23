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

import lombok.AllArgsConstructor;
import net.foulest.ospreyproxy.result.LookupResult;

/**
 * Enumeration of supported list descriptors, each with its URL, content format, short name for logging,
 * endpoint name for HTTP routing, the {@link LookupResult} to return when a host is found in the list,
 * and the refresh interval in seconds.
 * <p>
 * Adding a new local list requires only a new enum constant here — no changes to
 * {@link LocalListUtil} or {@link net.foulest.ospreyproxy.ProxyHandler} are needed.
 */
@AllArgsConstructor
public enum Descriptor {
    PHISH_DESTROY(
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt",
            Format.TEXT,
            "PhishDestroy",
            "phishdestroy",
            LookupResult.PHISHING,
            60L
    ),

    PHISHING_DATABASE(
            "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt",
            Format.TEXT,
            "Phishing.Database",
            "phishing-database",
            LookupResult.PHISHING,
            60L
    );

    final String url;
    final Format format;
    public final String shortName;

    /**
     * The HTTP endpoint path suffix for this list (e.g., {@code "phishdestroy"} → {@code POST /phishdestroy}).
     * Must be unique across all descriptors and must not collide with any provider endpoint name.
     */
    public final String endpointName;

    /**
     * The {@link LookupResult} to return when a host is found in this list.
     */
    public final LookupResult resultType;

    /**
     * How often to re-fetch this list, in seconds.
     */
    public final long refreshIntervalSeconds;
}
