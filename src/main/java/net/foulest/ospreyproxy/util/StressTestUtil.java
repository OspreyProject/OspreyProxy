package net.foulest.ospreyproxy.util;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Utility class for stress testing OspreyProxy without hitting upstream providers.
 * <p>
 * When stress test mode is enabled via 'ospreyproxy.stress-test-mode=true' in
 * application.properties, all upstream provider calls are bypassed and a fake
 * response is returned immediately. Every request is also assigned a unique
 * synthetic IP to simulate distinct users and exercise the rate limiter cache.
 * <p>
 * This mode must never be enabled in production.
 *
 * @author Foulest
 */
@Component
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class StressTestUtil {

    // Fake upstream response returned in stress test mode
    private static final String FAKE_RESPONSE = "{\"stress_test\": true, \"verdict\": \"safe\"}";

    // Whether stress test mode is active; injected from application.properties
    @Getter
    private static boolean enabled;

    @Value("${ospreyproxy.stress-test-mode:false}")
    public void setEnabled(boolean value) {
        enabled = value;
    }

    /**
     * Returns a fake upstream response for use in stress test mode.
     *
     * @return A JSON string simulating a provider response.
     */
    public static @NonNull String getFakeResponse() {
        return FAKE_RESPONSE;
    }

    /**
     * Generates a unique synthetic IP address for each request in stress test mode.
     * This exercises the Caffeine rate limiter cache with distinct keys rather than
     * all requests sharing the same IP, which would not reflect real-world behavior.
     *
     * @return A unique string that will be treated as a distinct IP by the rate limiter.
     */
    public static @NonNull String syntheticIp() {
        return UUID.randomUUID().toString();
    }
}
