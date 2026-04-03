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

    // ThreadLocal Mac to avoid getInstance() overhead on every call
    // Mac is not thread-safe, so ThreadLocal is required
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<Mac> IP_HMAC = ThreadLocal.withInitial(() -> {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(IP_SALT, "HmacSHA256"));
            return mac;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    });

    // Separate ThreadLocal Mac for URL hashing, keyed with URL_SALT
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<Mac> URL_HMAC = ThreadLocal.withInitial(() -> {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(URL_SALT, "HmacSHA256"));
            return mac;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    });

    // Cache for hashed IP addresses to improve performance and reduce CPU load on repeated hashes
    private static final Cache<String, String> IP_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();

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
     * Hashes the IP address using HMAC-SHA-256 with a random salt to produce a stable, non-reversible identifier.
     *
     * @param ip The IP address to hash.
     * @return A hexadecimal string representation of the hashed IP address.
     */
    static String hashIp(@NonNull String ip) {
        return IP_CACHE.get(ip, k -> {
            Mac mac = IP_HMAC.get();
            mac.reset();

            byte[] bytes = k.getBytes(StandardCharsets.UTF_8);
            byte[] hash = mac.doFinal(bytes);
            return HexFormat.of().formatHex(hash);
        });
    }

    /**
     * Hashes the URL using HMAC-SHA-256 with a separate salt to prevent correlation with IP hashes.
     *
     * @param url The URL to hash.
     * @return A hexadecimal string representation of the hashed URL, truncated to 16 bytes (32 hex chars).
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull String hashUrl(@NonNull String url) {
        Mac mac = URL_HMAC.get();
        mac.reset();
        byte[] digest = mac.doFinal(url.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest, 0, 16);
    }
}
