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
 * DNS RR type constants for the record types we care about in filtering responses.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Record {

    /**
     * The A record type, which maps a domain name to an IPv4 address.
     */
    public static final int A = 1;

    /**
     * The NS record type, which delegates a DNS zone to an authoritative name server.
     */
    public static final int NS = 2;

    /**
     * The CNAME record type, which maps a domain name to another domain name (canonical name).
     */
    public static final int CNAME = 5;
}
