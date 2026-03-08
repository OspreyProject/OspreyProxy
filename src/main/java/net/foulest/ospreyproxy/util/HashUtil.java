/*
 * OspreyProxy - backend code for our proxy server using Spring WebFlux.
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;

/**
 * Utility class for hashing IP addresses with a salt.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class HashUtil {

    // Random salt for hashing IPs; intentionally regenerated on each restart.
    // Hashes are used only for in-memory rate-limit bucket keys (Caffeine cache),
    // not persisted, so cross-restart consistency is unnecessary. Regeneration
    // improves privacy by preventing long-term IP correlation.
    private static final byte[] IP_SALT = generateSalt();

    // ThreadLocal MessageDigest to avoid MessageDigest.getInstance() on every call.
    // This is a static final field intended to live for the application's lifetime;
    // remove() is not needed because Netty event loop threads are long-lived and
    // terminated at shutdown, at which point the ThreadLocal is cleaned up.
    @SuppressWarnings("java:S5164")
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    });

    // Cache for hashed IP addresses to improve performance and reduce CPU load on repeated hashes
    private static final Cache<String, String> HASH_CACHE = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofHours(1))
            .maximumSize(100_000)
            .build();

    /**
     * Generates a random salt for hashing IP addresses to prevent rainbow table attacks.
     * Creates a new SecureRandom instance, which is acceptable because this method
     * is called exactly once at class load time ({@code IP_SALT} initialization).
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
     * Hashes the IP address using SHA-256 with a salt to prevent rainbow table attacks.
     * Caffeine's get() uses an optimistic fast-path for cache hits internally
     * without locking, so no manual getIfPresent() check is needed.
     * Uses ThreadLocal MessageDigest to avoid getInstance() overhead on misses.
     *
     * @param ip The IP address to hash.
     * @return A hexadecimal string representation of the hashed IP address.
     */
    public static String hashIp(@NonNull String ip) {
        return HASH_CACHE.get(ip, k -> {
            MessageDigest digest = SHA256_DIGEST.get();
            digest.reset();
            digest.update(IP_SALT);
            byte[] bytes = k.getBytes(StandardCharsets.UTF_8);
            byte[] hash = digest.digest(bytes);
            return HexFormat.of().formatHex(hash);
        });
    }
}
