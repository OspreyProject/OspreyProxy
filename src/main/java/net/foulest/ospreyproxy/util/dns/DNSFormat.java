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
package net.foulest.ospreyproxy.util.dns;

/**
 * Represents the format of a DNS provider's API.
 */
public enum DNSFormat {

    /**
     * {@code ?name=<host>} URL encoding + binary DNS wire response.
     * <p>
     * Example: Control D ({@code freedns.controld.com}).
     */
    NAME_MESSAGE,

    /**
     * {@code ?name=<host>} URL encoding + JSON response.
     * <p>
     * Example: Cloudflare ({@code cloudflare-dns.com}).
     */
    NAME_JSON,

    /**
     * Base64url-encoded DNS wire query appended to the URL + binary DNS wire response.
     * <p>
     * Example: standard RFC 8484 GET binding.
     */
    PATH_MESSAGE,

    /**
     * Base64url-encoded DNS wire query appended to the URL + JSON response.
     */
    PATH_JSON,
}
