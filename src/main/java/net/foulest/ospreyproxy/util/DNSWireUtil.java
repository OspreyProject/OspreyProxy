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
package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Builds DNS wire-format query packets and encodes them for use in DoH requests.
 * <p>
 * Mirrors {@code UrlHelpers.encodeDNSQuery()} from the Osprey browser extension.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class DNSWireUtil {

    // DNS record type A (IPv4 address)
    private static final int TYPE_A = 1;

    /**
     * Builds a minimal DNS wire-format query packet for the given hostname and record type,
     * then returns it as a Base64url-encoded string suitable for use in a {@code ?dns=} parameter.
     * <p>
     * Packet layout:
     * <ul>
     *   <li>12-byte header: ID=0x0000, flags=0x0100 (RD set), QDCOUNT=1, all others 0</li>
     *   <li>QNAME: each label prefixed by its length byte, terminated by 0x00</li>
     *   <li>QTYPE: 2 bytes big-endian</li>
     *   <li>QCLASS: 0x00 0x01 (IN)</li>
     * </ul>
     *
     * @param host The hostname to query. Must contain only {@code [a-zA-Z0-9._-]}.
     * @param type The DNS record type (0–65535). Use {@link #TYPE_A} for A records.
     * @return Base64url-encoded wire-format DNS query (no padding).
     * @throws IllegalArgumentException If the hostname or type is invalid.
     */
    @SuppressWarnings("NestedMethodCall")
    private static @NonNull String buildBase64Query(@NonNull String host, int type) {
        if (type < 0 || type > 65535) {
            throw new IllegalArgumentException("type must be a valid DNS record type (0-65535): " + type);
        }

        // Strip trailing dot; DNS wire format carries labels explicitly
        String stripped = host.trim();
        if (!stripped.isEmpty() && stripped.charAt(stripped.length() - 1) == '.') {
            stripped = stripped.substring(0, stripped.length() - 1);
        }

        // Reject domains with invalid characters (mirrors extension validation)
        if (!stripped.matches("^[a-zA-Z0-9._-]+$")) {
            throw new IllegalArgumentException("Domain contains invalid characters: " + stripped);
        }

        // Reject overly long domains (max 253 chars per RFC 1035)
        if (stripped.length() > 253) {
            throw new IllegalArgumentException("Domain exceeds maximum length: " + stripped.length());
        }

        // Header: ID=0x0000, flags=0x0100 (RD), QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0
        byte[] header = {
                0x00, 0x00, // ID
                0x01, 0x00, // flags: standard query, recursion desired
                0x00, 0x01, // QDCOUNT = 1
                0x00, 0x00, // ANCOUNT
                0x00, 0x00, // NSCOUNT
                0x00, 0x00  // ARCOUNT
        };

        // Build QNAME: length-prefixed labels terminated by 0x00
        ByteArrayOutputStream qname = new ByteArrayOutputStream();
        for (String label : stripped.split("\\.", -1)) {
            byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);

            if (labelBytes.length == 0 || labelBytes.length > 63) {
                throw new IllegalArgumentException("Invalid label length in domain '" + stripped + "': " + labelBytes.length);
            }

            qname.write(labelBytes.length);
            qname.write(labelBytes, 0, labelBytes.length);
        }
        qname.write(0x00); // end of QNAME

        // QTYPE (2 bytes big-endian) + QCLASS IN (0x00 0x01)
        byte[] qtypeAndClass = {
                (byte) (type >>> 8 & 0xFF),
                (byte) (type & 0xFF),
                0x00, 0x01  // IN
        };

        // Assemble the full packet
        byte[] qnameBytes = qname.toByteArray();
        byte[] packet = new byte[header.length + qnameBytes.length + qtypeAndClass.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(qnameBytes, 0, packet, header.length, qnameBytes.length);
        System.arraycopy(qtypeAndClass, 0, packet, header.length + qnameBytes.length, qtypeAndClass.length);

        // Base64url encode with no padding (mirrors btoa + replaceAll in the extension)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(packet);
    }

    /**
     * Convenience overload for A record queries.
     *
     * @param host The hostname to query.
     * @return Base64url-encoded wire-format DNS query for an A record.
     */
    static @NonNull String buildBase64Query(@NonNull String host) {
        return buildBase64Query(host, TYPE_A);
    }

    /**
     * URL-encodes a hostname for use in {@code ?name=} DoH JSON parameters.
     * Used by Cloudflare's JSON-based DoH endpoint.
     *
     * @param host The hostname to encode.
     * @return URL-encoded hostname string.
     */
    static @NonNull String encodeHostParam(@NonNull String host) {
        return URLEncoder.encode(host, StandardCharsets.UTF_8);
    }
}
