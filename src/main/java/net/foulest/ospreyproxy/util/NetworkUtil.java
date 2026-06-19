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
import org.apache.hc.client5.http.DnsResolver;
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Utility class for checking if an IP address or hostname is private/internal to prevent SSRF attacks.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class NetworkUtil {

    /**
     * Custom {@link DnsResolver} that validates every resolved IP against the private/internal
     * address blocklist in {@link NetworkUtil} before returning it to the connection manager.
     */
    public static final DnsResolver DNS_RESOLVER = new DnsResolver() {

        /**
         * Resolves {@code host} to a list of safe (non-private) addresses.
         * Called by the connection manager before opening a socket.
         *
         * @param host The hostname to resolve.
         * @return An array of safe {@link InetAddress} objects for the given host.
         */
        @Override
        public InetAddress @NonNull [] resolve(String host) throws UnknownHostException {
            InetAddress[] resolved = InetAddress.getAllByName(host);
            List<InetAddress> safe = new ArrayList<>(resolved.length);

            for (InetAddress addr : resolved) {
                if (isPrivateAddress(addr)) {
                    throw new UnknownHostException("Blocked: '" + host + "' resolved to private address");
                }

                safe.add(addr);
            }

            if (safe.isEmpty()) {
                throw new UnknownHostException("No safe addresses resolved for: " + host);
            }
            return safe.toArray(new InetAddress[0]);
        }

        /**
         * Returns the canonical hostname for the given host.
         *
         * @param host The hostname to resolve.
         * @return The canonical hostname.
         */
        @Override
        @Contract(value = "_ -> param1", pure = true)
        public String resolveCanonicalHostname(String host) {
            return host;
        }
    };

    /**
     * Pattern to match illegal characters in URLs that should be percent-encoded.
     */
    private static final Pattern ENCODING_PATTERN = Pattern.compile("%(?![0-9a-fA-F]{2})");

    /**
     * Checks if an {@link InetAddress} is private or internal.
     * Used by the SSRF-safe DNS resolver at connection time.
     *
     * @param addr The {@link InetAddress} to lookup.
     * @return {@code true} if the address is private/internal, {@code false} otherwise.
     */
    @SuppressWarnings("NestedMethodCall")
    private static boolean isPrivateAddress(@NonNull InetAddress addr) {
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

            // "This network" range (0.0.0.0/8, RFC 1122)
            if (first == 0) {
                return true;
            }

            // Carrier-grade NAT range (100.64.0.0/10)
            if (first == 100 && second >= 64 && second <= 127) {
                return true;
            }

            // IANA documentation ranges (RFC 5737)
            if (first == 192 && second == 0 && (bytes[2] & 0xFF) == 2) {
                return true;
            }
            if (first == 192 && second == 0 && (bytes[2] & 0xFF) == 0) {
                return true;
            }
            if (first == 198 && second == 51 && (bytes[2] & 0xFF) == 100) {
                return true;
            }
            if (first == 198 && second >= 18 && second <= 19) {
                return true;
            }
            if (first == 203 && second == 0 && (bytes[2] & 0xFF) == 113) {
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

            // Block IPv4-compatible IPv6 addresses (::a.b.c.d, deprecated RFC 4291) which
            // embed an IPv4 address in the last 4 bytes with bytes 0-11 all zero.
            // (::1 and :: are already caught by the loopback/anyLocal checks above.)
            boolean isV4Compatible = true;

            for (int i = 0; i < 12; i++) {
                if (bytes[i] != 0) {
                    isV4Compatible = false;
                    break;
                }
            }

            if (isV4Compatible) {
                return isEmbeddedV4Private(Arrays.copyOfRange(bytes, 12, 16));
            }

            // Block the NAT64 well-known prefix (64:ff9b::/96, RFC 6052) which embeds an
            // IPv4 address in the last 4 bytes; on NAT64 networks, 64:ff9b::7f00:1 routes
            // to 127.0.0.1. Also block the local-use NAT64 prefix (64:ff9b:1::/48, RFC 8215)
            // outright, since its IPv4 embedding position varies by deployment.
            if (bytes[0] == 0x00 && (bytes[1] & 0xFF) == 0x64
                    && (bytes[2] & 0xFF) == 0xFF && (bytes[3] & 0xFF) == 0x9B) {
                if (bytes[4] == 0x01) {
                    return true; // 64:ff9b:1::/48 local-use prefix
                }

                boolean isWellKnown = true;

                for (int i = 4; i < 12; i++) {
                    if (bytes[i] != 0) {
                        isWellKnown = false;
                        break;
                    }
                }

                if (isWellKnown) {
                    return isEmbeddedV4Private(Arrays.copyOfRange(bytes, 12, 16));
                }
            }
        }
        return false;
    }

    /**
     * Checks an embedded IPv4 address (extracted from a mapped/compatible/NAT64/6to4
     * IPv6 address) against the private-address rules. Treats malformed bytes as private.
     */
    private static boolean isEmbeddedV4Private(byte @NonNull [] v4Bytes) {
        try {
            return isPrivateAddress(InetAddress.getByAddress(v4Bytes));
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("Invalid embedded IPv4 address ({})", e.getClass().getName(), e);
            return true;
        }
    }

    /**
     * Checks if the {@code host} is private or internal to prevent SSRF attacks.
     * Only performs string-based hostname checks here; IP-level blocking
     * is handled by {@code DNS_RESOLVER} at connection time to avoid
     * DNS rebinding (TOCTOU) vulnerabilities from double-resolution.
     *
     * @param host The hostname to lookup.
     * @return {@code true} if the host is considered private/internal, {@code false} otherwise.
     */
    public static boolean isPrivateHost(@NonNull String host) {
        host = normalize(host);

        // Checks if the host is empty
        if (host.isEmpty()) {
            return true;
        }

        // Block known internal hostnames by name
        if ("localhost".equals(host)
                || "local".equals(host)
                || "internal".equals(host)
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
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given {@code host} string is an IP address literal (IPv4 or IPv6)
     * without performing any DNS resolution.
     * <p>
     * IPv6 literals from URI.getHost() come without brackets (e.g., "::1"), and a
     * colon can't appear in a hostname, so any colon means IPv6. IPv4 must be strict
     * dotted-decimal: exactly four octets, each 0-255, digits only. Hex notation
     * ("0x7f.0.0.1") and decimal-integer forms are intentionally NOT treated as
     * literals; they fall through to hostname validation, fail DoH resolution, and
     * are independently rejected by the connection-time DNS resolver.
     */
    static boolean isIpLiteral(@NonNull String host) {
        return host.indexOf(':') >= 0 || isDottedDecimalIpv4(host);
    }

    /**
     * Strictly validates that {@code host} is a well-formed IPv6 literal in bare form
     * (no brackets, no zone identifier), e.g. "::1" or "::ffff:192.168.1.1".
     * <p>
     * Unlike {@link #isIpLiteral(String)}, which treats any colon-containing string as
     * an IPv6 literal, this parses the literal and rejects malformed input. A colon can
     * never appear in a hostname, so {@link InetAddress#getByName(String)} parses the
     * candidate as a numeric literal without performing any DNS resolution.
     *
     * @param host The candidate host (expected bare and lowercased).
     * @return {@code true} if {@code host} is a syntactically valid IPv6 literal.
     */
    static boolean isIpv6Literal(@NonNull String host) {
        if (host.indexOf(':') < 0
                || host.indexOf('%') >= 0
                || host.indexOf('[') >= 0
                || host.indexOf(']') >= 0) {
            return false;
        }

        try {
            InetAddress.getByName(host);
            return true;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
            return false;
        }
    }

    /**
     * Validates strict dotted-decimal IPv4 (four octets, 0-255, no signs, no hex,
     * parts of at most 3 digits).
     */
    static boolean isDottedDecimalIpv4(@NonNull String host) {
        String[] parts = host.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }

            int value = 0;

            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);

                if (c < '0' || c > '9') {
                    return false;
                }

                value = value * 10 + (c - '0');
            }

            if (value > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * Encodes illegal characters that might be present in URLs.
     *
     * @param url The URL string to encode.
     * @return The encoded URL.
     */
    static @NonNull String encodeIllegalUriChars(@NonNull String url) {
        url = Normalizer.normalize(url, Normalizer.Form.NFC);
        String result = ENCODING_PATTERN.matcher(url).replaceAll("%25");

        return result.replace("[", "%5B")
                .replace("]", "%5D")
                .replace("|", "%7C")
                .replace("{", "%7B")
                .replace("}", "%7D")
                .replace("^", "%5E")
                .replace("`", "%60")
                .replace(" ", "%20");
    }

    /**
     * Normalizes a domain name by stripping whitespace, converting to lowercase, and removing any trailing dots.
     *
     * @param name The domain name to normalize.
     * @return The normalized domain name, suitable for case-insensitive comparison.
     *         For example, "Example.COM. " becomes "example.com".
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull String normalize(@NonNull String name) {
        name = name.strip().toLowerCase(Locale.ROOT);
        return !name.isEmpty() && name.charAt(name.length() - 1) == '.' ? name.substring(0, name.length() - 1) : name;
    }
}
