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
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Utility class for stress testing OspreyProxy without hitting upstream providers.
 * <p>
 * When stress test mode is enabled via 'ospreyproxy.stress-test-mode=true' in
 * application.properties, all upstream provider calls are bypassed and a fake
 * response is returned immediately. Every request is also assigned a unique
 * synthetic IP to simulate distinct users and exercise the rate limiter cache.
 * <p>
 * This mode must never be enabled in production.
 */
@Component
// Private constructor is accessible to Spring via CGLIB reflection-based instantiation.
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class StressTestUtil {

    // Whether stress test mode is active; injected from application.properties.
    // Volatile for visibility: written by Spring's main thread via @Value setter,
    // read by Netty event loop threads during request handling.
    @Getter
    public static volatile boolean enabled;

    // Instance method is required for Spring @Value injection; cannot be static.
    @SuppressWarnings({"MethodMayBeStatic", "java:S2696"})
    @Value("${ospreyproxy.stress-test-mode:false}")
    public void setEnabled(boolean value) {
        enabled = value;
    }

    /**
     * Generates a synthetic IP address for each request in stress test mode.
     * This exercises the Caffeine rate limiter cache with distinct keys rather than
     * all requests sharing the same IP, which would not reflect real-world behavior.
     *
     * @return A string that will be treated as a distinct IP by the rate limiter.
     */
    public static @NonNull String syntheticIp() {
        long bits = ThreadLocalRandom.current().nextLong();

        // Extract 2 octets from the random long for ~65K unique IPs (10.X.Y.1)
        int b = (int) ((bits >>> 8) & 0xFF);    // 0-255
        int c = (int) ((bits >>> 16) & 0xFF);    // 0-255

        // Write directly into a char array to avoid StringBuilder allocation
        char[] buf = new char[12]; // max "10.255.255.1"
        buf[0] = '1';
        buf[1] = '0';
        buf[2] = '.';

        int pos = 3;
        pos = writeOctet(buf, pos, b);

        buf[pos] = '.';
        pos++;

        pos = writeOctet(buf, pos, c);

        buf[pos] = '.';
        pos++;

        buf[pos] = '1';
        pos++;
        return new String(buf, 0, pos);
    }

    /**
     * Writes an integer octet (0-255) into the char buffer at the given position.
     *
     * @return The new position after writing.
     */
    @SuppressWarnings("CharUsedInArithmeticContext")
    private static int writeOctet(char @NonNull [] buf, int pos, int value) {
        if (value >= 100) {
            buf[pos] = (char) ('0' + value / 100);
            pos++;

            buf[pos] = (char) ('0' + (value / 10) % 10);
            pos++;
        } else if (value >= 10) {
            buf[pos] = (char) ('0' + value / 10);
            pos++;
        }

        buf[pos] = (char) ('0' + value % 10);
        pos++;
        return pos;
    }
}
