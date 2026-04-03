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
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Utility class for building DNS queries in wire format and encoding them for DoH (DNS over HTTPS) requests.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DNSUtil {

    // Pattern for validating domain names
    private static final Pattern VALID_DOMAIN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    /**
     * Builds a Base64url-encoded wire-format DNS query for the given hostname and record type.
     *
     * @param host The hostname to query. Must contain only {@code [a-zA-Z0-9._-]}.
     * @param type The DNS record type (0–65535). Use constants from {@link Record} for common types.
     * @return Base64url-encoded wire-format DNS query (no padding).
     * @throws IllegalArgumentException If the hostname or type is invalid.
     */
    private static @NonNull String buildBase64Query(@NonNull String host, int type) {
        // Checks if the DNS record type is valid
        if (type < 0 || type > 65535) {
            throw new IllegalArgumentException("Invalid DNS record type: " + type);
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
        return buildBase64Query(host, Record.A);
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
    @SuppressWarnings("NestedMethodCall")
    private static @NonNull String getStrippedHost(@NonNull String host) {
        String stripped = host.trim();

        if (!stripped.isEmpty() && stripped.charAt(stripped.length() - 1) == '.') {
            stripped = stripped.substring(0, stripped.length() - 1);
        }

        if (!VALID_DOMAIN.matcher(stripped).matches()) {
            throw new IllegalArgumentException("Domain contains invalid characters");
        }

        if (stripped.length() > 253) {
            throw new IllegalArgumentException("Domain exceeds maximum length: " + stripped.length());
        }
        return stripped;
    }

    /**
     * Walks through the answer records in the raw DNS message response
     * and tests each record against the given predicate.
     *
     * @param response The raw DNS message response bytes.
     * @param predicate The predicate to test each answer record against. Takes the RR type and RDATA bytes as input.
     * @return {@code true} if any answer record matches the predicate, {@code false} otherwise or if the response is malformed.
     */
    public static boolean walkAnswers(byte @NonNull [] response, @NonNull RecordPredicate predicate) {
        if (response.length < 12) {
            return false;
        }

        int anCount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);

        if (anCount == 0 || anCount > 1000) {
            return false;
        }

        int off = 12;
        int qdCount = ((response[4] & 0xFF) << 8) | (response[5] & 0xFF);

        for (int i = 0; i < qdCount; i++) {
            off = skipName(response, off);
            off += 4;

            if (off > response.length) {
                return false;
            }
        }

        for (int i = 0; i < anCount; i++) {
            if (off >= response.length) {
                break;
            }

            off = skipName(response, off);

            if (off + 10 > response.length) {
                break;
            }

            int rrType = ((response[off] & 0xFF) << 8) | (response[off + 1] & 0xFF);
            off += 8;

            int rdLength = ((response[off] & 0xFF) << 8) | (response[off + 1] & 0xFF);
            off += 2;

            if (off + rdLength > response.length) {
                break;
            }

            byte[] rdata = new byte[rdLength];
            System.arraycopy(response, off, rdata, 0, rdLength);
            off += rdLength;

            if (predicate.test(rrType, rdata)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Skips over a domain name in the raw DNS message bytes, starting at the given offset.
     *
     * @param data The raw byte array of the DNS message.
     * @param off The offset to start skipping from. Should point to the beginning of a domain name (QNAME or NAME field).
     * @return The offset immediately after the domain name. Handles both uncompressed and compressed names.
     *         Returns an offset beyond the array length if the name is malformed.
     */
    @Contract(pure = true)
    private static int skipName(byte @NonNull [] data, int off) {
        int steps = 0;

        while (off < data.length && steps < data.length) {
            steps++;
            int len = data[off] & 0xFF;

            if ((len & 0xC0) == 0xC0) {
                off += 2;
                break;
            }

            if (len == 0) {
                off += 1;
                break;
            }

            off += 1 + len;
        }
        return off;
    }

    /**
     * Parses a domain name from the given RDATA bytes. Handles uncompressed names only, as expected in CNAME RDATA.
     *
     * @param rdata The raw RDATA bytes from a CNAME record, which should contain the domain name in DNS label format.
     *              Compression pointers are not supported; if encountered, name parsing stops and the partial result
     *              (which may be empty) is returned.
     * @return The parsed domain name as a String, without the trailing dot.
     *         Returns an empty string if the RDATA is malformed.
     */
    public static @NonNull String parseName(byte @NonNull [] rdata) {
        StringBuilder sb = new StringBuilder();
        int off = 0;
        boolean first = true;

        while (off < rdata.length) {
            int len = rdata[off] & 0xFF;

            if (len == 0) {
                break;
            }

            if ((len & 0xC0) == 0xC0) {
                break;
            }

            off++;

            if (off + len > rdata.length) {
                break;
            }

            if (!first) {
                sb.append('.');
            }

            sb.append(new String(rdata, off, len, StandardCharsets.UTF_8));
            off += len;
            first = false;
        }
        return sb.toString();
    }

    /**
     * Parses an IPv4 address from the given RDATA bytes. Expects exactly 4 bytes for a valid IPv4 address.
     *
     * @param rdata The raw RDATA bytes from an A record.
     * @return The IPv4 address in dotted-decimal notation (e.g. "192.168.1.1")
     */
    @Contract(pure = true)
    public static @Nullable String parseIPv4(byte @NonNull [] rdata) {
        if (rdata.length != 4) {
            return null;
        }
        return (rdata[0] & 0xFF) + "." + (rdata[1] & 0xFF) + "." + (rdata[2] & 0xFF) + "." + (rdata[3] & 0xFF);
    }
}
