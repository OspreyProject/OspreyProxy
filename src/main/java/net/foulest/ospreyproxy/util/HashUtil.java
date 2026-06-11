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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;

/**
 * Utility class for hashing IP addresses and URLs in a non-reversible way using HMAC with random salts.
 * This allows us to generate stable identifiers for IPs and URLs without storing the original values,
 * which is important for privacy and security.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class HashUtil {

    // Random salt for hashing IPs; intentionally regenerated on each restart
    private static final byte[] IP_SALT = generateSalt();

    // Separate salt for hashing URLs; kept independent of IP_SALT so the two
    // hash spaces cannot be correlated with each other
    private static final byte[] URL_SALT = generateSalt();

    // Algorithm name for HMAC
    private static final String HMAC_SHA_256 = "HmacSHA256";

    // Cache for hashed IP addresses to improve performance and reduce CPU load on repeated hashes
    private static final Cache<String, String> IP_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();

    // Prototype Mac instances pre-initialized with the respective salts,
    // to be cloned for each hash operation
    private static final Mac IP_MAC_PROTOTYPE = createMac(IP_SALT);
    private static final Mac URL_MAC_PROTOTYPE = createMac(URL_SALT);

    /**
     * Creates a Mac instance initialized with the given salt for HMAC operations.
     *
     * @param salt The salt to use for initializing the Mac instance.
     * @return A Mac instance ready for hashing with the specified salt.
     */
    private static @NonNull Mac createMac(byte @NonNull [] salt) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA_256);
            mac.init(new SecretKeySpec(salt, HMAC_SHA_256));
            return mac;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw new IllegalStateException(HMAC_SHA_256 + " not available", e);
        }
    }

    /**
     * Generates a random salt for hashing IP addresses to prevent rainbow table attacks.
     * Creates a new {@link SecureRandom} instance, which is acceptable because this method
     * is called exactly twice at class load time ({@code IP_SALT} and {@code URL_SALT} initialization).
     *
     * @return A random byte array to be used as a salt for hashing IP addresses.
     */
    @SuppressWarnings("java:S2119")
    private static byte @NonNull [] generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Clones the prototype Mac (cheap: copies pre-keyed state, no key schedule).
     * Falls back to a fresh instance if the provider doesn't support cloning.
     *
     * @param prototype The prototype Mac instance to clone.
     * @param salt The salt to use if cloning is not supported.
     * @return A Mac instance initialized with the same salt as the prototype.
     */
    private static @NonNull Mac newMac(@NonNull Mac prototype, byte @NonNull [] salt) {
        try {
            return (Mac) prototype.clone();
        } catch (CloneNotSupportedException ignored) {
            return createMac(salt);
        }
    }

    /**
     * Hashes the IP address using HMAC-SHA-256 with a random salt to produce a stable, non-reversible identifier.
     *
     * @param ip The IP address to hash.
     * @return A hexadecimal string representation of the hashed IP address.
     */
    static String hashIp(@NonNull String ip) {
        return IP_CACHE.get(ip, (String ipString) -> {
            Mac mac = newMac(IP_MAC_PROTOTYPE, IP_SALT);
            byte[] hash = mac.doFinal(ipString.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        });
    }

    /**
     * Hashes the URL using HMAC-SHA-256 with a separate salt to prevent correlation with IP hashes.
     *
     * @param url The URL to hash.
     * @return A hexadecimal string representation of the hashed URL.
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull String hashUrl(@NonNull String url) {
        Mac mac = newMac(URL_MAC_PROTOTYPE, URL_SALT);
        byte[] digest = mac.doFinal(url.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }
}
