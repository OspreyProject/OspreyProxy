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
 * Represents a descriptor for a list provider, containing all necessary information to fetch and interpret the list.
 */
@AllArgsConstructor
public enum Descriptor {

    /**
     * PhishDestroy
     */
    PHISH_DESTROY(
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt",
            Format.TEXT,
            "PhishDestroy",
            "phishdestroy",
            LookupResult.PHISHING,
            120L
    ),

    /**
     * Phishing.Database
     */
    PHISHING_DATABASE(
            "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt",
            Format.TEXT,
            "Phishing.Database",
            "phishing-database",
            LookupResult.PHISHING,
            120L
    );

    final String url;
    final Format format;

    /**
     * A human-readable name for this list, used in logging.
     */
    public final String shortName;

    /**
     * The endpoint name for this list, used in configuration and routing.
     */
    public final String endpointName;

    /**
     * The type of result to return when a domain is found in this list.
     */
    public final LookupResult resultType;

    /**
     * The interval in seconds at which this list should be refreshed.
     */
    public final long refreshIntervalSeconds;
}
