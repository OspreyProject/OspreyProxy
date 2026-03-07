package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Utility class for checking if an IP address or hostname is private/internal to prevent SSRF attacks.
 *
 * @author Foulest
 */
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

        // Block carrier-grade NAT range (100.64.0.0/10)
        if (addr instanceof Inet4Address v4) {
            byte[] bytes = v4.getAddress();
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            return first == 100 && second >= 64 && second <= 127;
        }

        // Block IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1, ::ffff:169.254.169.254)
        if (addr instanceof Inet6Address v6) {
            byte[] bytes = v6.getAddress();
            int firstByte = addr.getAddress()[0] & 0xFF;
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
                } catch (UnknownHostException e) {
                    return true;
                }
            }

            // Block IPv6 unique-local addresses (fc00::/7, e.g., fd00:ec2::254 AWS metadata)
            if ((firstByte & 0xFE) == 0xFC) {
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
                } catch (UnknownHostException e) {
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
    public static boolean isPrivateHost(@NonNull String host) {
        // Block known internal hostnames by name
        if (host.equals("localhost")
                || host.endsWith(".local")
                || host.endsWith(".internal")
                || host.endsWith(".localhost")) {
            return true;
        }

        // Block raw IP addresses used directly as hostnames.
        // Uses numeric format detection to avoid DNS resolution (which would
        // reintroduce the TOCTOU window this method is designed to avoid).
        // IPv4 literals (e.g., "192.168.1.1") and IPv6 literals (e.g., "::1")
        // are detected by format and then checked against private ranges.
        if (isIpLiteral(host)) {
            try {
                InetAddress addr = InetAddress.getByName(host);
                return isPrivateAddress(addr);
            } catch (UnknownHostException e) {
                // Malformed IP literal; block it to be safe
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given host string is an IP address literal (IPv4 or IPv6)
     * without performing any DNS resolution.
     *
     * @param host The hostname to check.
     * @return True if the host looks like an IP literal, false if it's a domain name.
     */
    @SuppressWarnings("CharacterComparison")
    private static boolean isIpLiteral(@NonNull String host) {
        // IPv6 literals from URI.getHost() come without brackets (e.g., "::1")
        if (host.contains(":")) {
            return true;
        }

        // IPv4: all characters must be digits or dots, and must contain at least one dot
        if (host.contains(".")) {
            for (int i = 0; i < host.length(); i++) {
                char c = host.charAt(i);

                if (c != '.' && (c < '0' || c > '9')) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
