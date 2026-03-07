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
import java.util.HexFormat;

/**
 * Utility class for hashing IP addresses with a salt.
 *
 * @author Foulest
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class HashUtil {

    // IP salt for hashing to prevent rainbow table attacks
    private static final byte[] IP_SALT = generateSalt();

    // Cache for hashed IP addresses to improve performance and reduce CPU load on repeated hashes
    private static final Cache<String, String> HASH_CACHE = Caffeine.newBuilder()
            .maximumSize(100_000)
            .build();

    /**
     * Generates a random salt for hashing IP addresses to prevent rainbow table attacks.
     *
     * @return A random byte array to be used as a salt for hashing IP addresses.
     */
    private static byte @NonNull [] generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Hashes the IP address using SHA-256 with a salt to prevent rainbow table attacks.
     * Uses getIfPresent() fast-path to avoid Caffeine locking on cache hits,
     * and ThreadLocal MessageDigest to avoid getInstance() overhead on misses.
     *
     * @param ip The IP address to hash.
     * @return A hexadecimal string representation of the hashed IP address.
     */
    public static String hashIp(@NonNull String ip) {
        return HASH_CACHE.get(ip, k -> {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(IP_SALT);

                byte[] bytes = k.getBytes(StandardCharsets.UTF_8);
                byte[] hash = digest.digest(bytes);
                return HexFormat.of().formatHex(hash);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 not available", e);
            }
        });
    }
}
