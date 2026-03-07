package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jetbrains.annotations.NotNull;

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

    /**
     * Generates a random salt for hashing IP addresses to prevent rainbow table attacks.
     *
     * @return A random byte array to be used as a salt for hashing IP addresses.
     */
    private static byte @NotNull [] generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Hashes the IP address using SHA-256 with a salt to prevent rainbow table attacks.
     *
     * @param ip - The IP address to hash.
     * @return A hexadecimal string representation of the hashed IP address.
     */
    public static String hashIp(@NotNull String ip) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(IP_SALT);

            byte[] bytes = ip.getBytes(StandardCharsets.UTF_8);
            byte[] hash = digest.digest(bytes);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
