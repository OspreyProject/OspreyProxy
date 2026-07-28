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
package net.foulest.ospreyproxy.util.dns;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Utility class for DNS Accept header values.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Accept {

    /**
     * The MIME type for DNS-over-HTTPS responses in JSON format.
     */
    public static final String DNS_JSON = "application/dns-json";

    /**
     * The MIME type for DNS-over-HTTPS responses in binary format.
     */
    public static final String DNS_MESSAGE = "application/dns-message";
}
