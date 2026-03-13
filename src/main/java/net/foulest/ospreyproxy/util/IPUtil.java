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
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;

/**
 * Utility class for checking if an IP address or hostname is private/internal to prevent SSRF attacks.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class IPUtil {

    /**
     * Checks if an InetAddress is private or internal.
     * Used by the SSRF-safe DNS resolver at connection time.
     *
     * @param addr The InetAddress to check.
     * @return True if the address is private/internal, false otherwise.
     */
    public static boolean isPrivateAddress(@NonNull InetAddress addr) {
        // Block standard private and special-use ranges
        if (addr.isLoopbackAddress()
                || addr.isSiteLocalAddress()
                || addr.isLinkLocalAddress()
                || addr.isAnyLocalAddress()
                || addr.isMulticastAddress()) {
            return true;
        }

        // Block IPv4 ranges not covered by the standard InetAddress checks above
        if (addr instanceof Inet4Address v4) {
            byte[] bytes = v4.getAddress();
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;

            // Limited broadcast address (255.255.255.255)
            if (first == 255 && bytes[1] == (byte) 0xFF
                    && bytes[2] == (byte) 0xFF && bytes[3] == (byte) 0xFF) {
                return true;
            }

            // Carrier-grade NAT range (100.64.0.0/10)
            if (first == 100 && second >= 64 && second <= 127) {
                return true;
            }

            // Class E reserved range (240.0.0.0/4)
            return (first & 0xF0) == 0xF0;
        }

        // Block IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1, ::ffff:169.254.169.254)
        if (addr instanceof Inet6Address v6) {
            byte[] bytes = v6.getAddress();
            boolean isMapped = true;

            // Check for ::ffff:x.x.x.x (IPv4-mapped IPv6)
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isMapped = false;
                    break;
                }
            }

            // The next 2 bytes must be 0xFF for it to be an IPv4-mapped address
            if (isMapped && bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF) {
                byte[] v4Bytes = Arrays.copyOfRange(bytes, 12, 16);

                try {
                    InetAddress v4Addr = InetAddress.getByAddress(v4Bytes);
                    return isPrivateAddress(v4Addr);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.warn("Invalid IPv4-mapped IPv6 address ({})", e.getClass().getName(), e);
                    return true;
                }
            }

            // Block IPv6 unique-local addresses (fc00::/7, e.g., fd00:ec2::254 AWS metadata)
            if (((bytes[0] & 0xFF) & 0xFE) == 0xFC) {
                return true;
            }

            // Block IPv6 Teredo addresses (2001:0000::/32) which can encapsulate arbitrary
            // private IPv4 addresses that Java's standard checks won't flag
            if ((bytes[0] & 0xFF) == 0x20 && bytes[1] == 0x01
                    && bytes[2] == 0x00 && bytes[3] == 0x00) {
                return true;
            }

            // Block IPv6 6to4 addresses (2002::/16) which embed IPv4 addresses in bytes 2-5
            // (e.g., 2002:a9fe:a9fe:: encapsulates 169.254.169.254)
            if ((bytes[0] & 0xFF) == 0x20 && (bytes[1] & 0xFF) == 0x02) {
                byte[] embeddedV4 = Arrays.copyOfRange(bytes, 2, 6);

                try {
                    InetAddress v4Addr = InetAddress.getByAddress(embeddedV4);

                    if (isPrivateAddress(v4Addr)) {
                        return true;
                    }
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.warn("Invalid 6to4 IPv6 address ({})", e.getClass().getName(), e);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the host is private or internal to prevent SSRF attacks.
     * Only performs string-based hostname checks here; IP-level blocking
     * is handled by SSRF_SAFE_DNS_RESOLVER at connection time to avoid
     * DNS rebinding (TOCTOU) vulnerabilities from double-resolution.
     *
     * @param host The hostname to check.
     * @return True if the host is considered private/internal, false otherwise.
     */
    public static boolean isPrivateHost(@NonNull String host, @NonNull String providerName) {
        // Strip trailing DNS root dot(s)
        int end = host.length();

        while (end > 0 && host.charAt(end - 1) == '.') {
            end--;
        }

        // If the host was entirely dots, treat it as invalid/private
        if (end == 0) {
            return true;
        }

        // Work with the stripped host for all subsequent checks
        // host is already lowercase at call sites; no re-lowercasing needed
        if (end < host.length()) {
            host = host.substring(0, end);
        }

        // Block known internal hostnames by name
        if (host.equals("localhost")
                || host.equals("local")
                || host.equals("internal")
                || host.endsWith(".local")
                || host.endsWith(".internal")
                || host.endsWith(".localhost")) {
            return true;
        }

        // Block raw IP addresses used directly as hostnames
        if (isIpLiteral(host)) {
            try {
                InetAddress addr = InetAddress.getByName(host);
                return isPrivateAddress(addr);
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                log.warn("[{}] Blocked request with invalid IP literal ({})", providerName, e.getClass().getName());
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given host string is an IP address literal (IPv4 or IPv6)
     * without performing any DNS resolution.
     *
     * <p>This is a fast format-detection heuristic, not a full IP validator.
     * Malformed inputs (e.g., "..." or "1.2.3.4.5.6") are intentionally accepted
     * here because the caller ({@link #isPrivateHost}) passes the result to
     * {@code InetAddress.getByName()}, which performs strict validation and throws
     * {@code UnknownHostException} on invalid literals (caught and treated as blocked).
     *
     * @param host The hostname from {@code URI.getHost()}, which never contains a port
     *             component (e.g., "example.com:8080" → "example.com", "[::1]:8080" → "::1").
     * @return True if the host looks like an IP literal, false if it's a domain name.
     */
    @SuppressWarnings("CharacterComparison")
    private static boolean isIpLiteral(@NonNull String host) {
        // IPv6 literals from URI.getHost() come without brackets (e.g., "::1").
        // Port-separated colons (e.g., "host:8080") cannot appear here because
        // URI.getHost() returns only the host component with the port stripped.
        if (host.contains(":")) {
            return true;
        }

        // IPv4 heuristic: contains a dot and all chars are hex-digits, dots, or hex prefix markers
        // (0-9, a-f, A-F, x, X). This catches both standard decimal dotted-quad notation
        // (e.g., "192.168.1.1") and hex-octet notation (e.g., "0x7f.0.0.1").
        // Intentionally loose: malformed inputs (e.g., "...", "1.2.3.4.5.6") are caught
        // by InetAddress.getByName() in the caller and treated as blocked.
        if (host.contains(".")) {
            for (int i = 0; i < host.length(); i++) {
                char c = host.charAt(i);

                if (c != '.' && c != 'x' && c != 'X'
                        && !(c >= '0' && c <= '9')
                        && !(c >= 'a' && c <= 'f')
                        && !(c >= 'A' && c <= 'F')) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
