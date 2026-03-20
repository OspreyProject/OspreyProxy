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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import net.foulest.ospreyproxy.util.PatternUtil;
import org.jspecify.annotations.NonNull;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class for building DNS queries in wire format and encoding them for DoH (DNS over HTTPS) requests.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DNSWireUtil {

    /**
     * Builds a Base64url-encoded wire-format DNS query for the given hostname and record type.
     *
     * @param host The hostname to query. Must contain only {@code [a-zA-Z0-9._-]}.
     * @param type The DNS record type (0–65535). Use constants from {@link DNSRecords} for common types.
     * @return Base64url-encoded wire-format DNS query (no padding).
     * @throws IllegalArgumentException If the hostname or type is invalid.
     */
    private static @NonNull String buildBase64Query(@NonNull String host, int type) {
        // Checks if the DNS record type is valid
        if (type < 0 || type > 65535) {
            throw new IllegalArgumentException("type must be a valid DNS record type (0-65535): " + type);
        }

        String stripped = getStrippedHost(host);

        // Header: ID=0x0000, flags=0x0100 (RD), QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0
        byte[] header = {
                0x00, 0x00, // ID
                0x01, 0x00, // flags: standard query, recursion desired
                0x00, 0x01, // QDCOUNT = 1
                0x00, 0x00, // ANCOUNT
                0x00, 0x00, // NSCOUNT
                0x00, 0x00  // ARCOUNT
        };

        ByteArrayOutputStream qname = new ByteArrayOutputStream();

        // Build QNAME: length-prefixed labels terminated by 0x00
        for (String label : stripped.split("\\.", -1)) {
            byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);

            // Checks if the label length is valid
            if (labelBytes.length == 0 || labelBytes.length > 63) {
                throw new IllegalArgumentException("Invalid label length in domain: " + labelBytes.length);
            }

            qname.write(labelBytes.length);
            qname.write(labelBytes, 0, labelBytes.length);
        }

        // End of QNAME
        qname.write(0x00);

        // QTYPE (2 bytes big-endian) + QCLASS IN (0x00 0x01)
        byte[] qtypeAndClass = {
                (byte) (type >>> 8 & 0xFF),
                (byte) (type & 0xFF),
                0x00, 0x01  // IN
        };

        // Assembles the full packet
        byte[] qnameBytes = qname.toByteArray();
        byte[] packet = new byte[header.length + qnameBytes.length + qtypeAndClass.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(qnameBytes, 0, packet, header.length, qnameBytes.length);
        System.arraycopy(qtypeAndClass, 0, packet, header.length + qnameBytes.length, qtypeAndClass.length);

        // Encodes the packet with Base64 and returns it
        return Base64.getUrlEncoder().withoutPadding().encodeToString(packet);
    }

    /**
     * Builds a Base64url-encoded wire-format DNS query for the given hostname, using record type A (IPv4 address).
     *
     * @param host The hostname to query.
     * @return Base64url-encoded wire-format DNS query for an A record.
     */
    public static @NonNull String buildBase64Query(@NonNull String host) {
        return buildBase64Query(host, DNSRecords.A);
    }

    /**
     * URL-encodes a hostname for use in {@code ?name=} DoH JSON parameters.
     *
     * @param host The hostname to encode.
     * @return URL-encoded hostname string.
     */
    public static @NonNull String encodeHostParam(@NonNull String host) {
        String stripped = getStrippedHost(host);
        return URLEncoder.encode(stripped, StandardCharsets.UTF_8);
    }

    /**
     * Strips whitespace and trailing dots from the hostname,
     * and validates it against allowed characters and length.
     *
     * @param host The hostname to process.
     * @return The stripped and validated hostname.
     */
    private static @NonNull String getStrippedHost(@NonNull String host) {
        String stripped = host.trim();

        if (!stripped.isEmpty() && stripped.charAt(stripped.length() - 1) == '.') {
            stripped = stripped.substring(0, stripped.length() - 1);
        }

        if (!PatternUtil.VALID_DOMAIN.matcher(stripped).matches()) {
            throw new IllegalArgumentException("Domain contains invalid characters");
        }

        if (stripped.length() > 253) {
            throw new IllegalArgumentException("Domain exceeds maximum length: " + stripped.length());
        }
        return stripped;
    }
}
