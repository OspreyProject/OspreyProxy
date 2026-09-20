/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.services;

import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;

class CircuitBreakerServiceTest {

    @Test
    void recordsSuccessAndRegistersEachProviderOnlyOnce() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.of(CircuitBreakerConfig.ofDefaults());
        CircuitBreakerService service = new CircuitBreakerService(registry);

        Assertions.assertThat(service.isOpen("provider")).isFalse();
        service.recordSuccess("provider", 12);
        service.recordSuccess("provider", 13);

        Assertions.assertThat(registry.circuitBreaker("provider").getMetrics().getNumberOfSuccessfulCalls()).isEqualTo(2);
    }

    @Test
    void opensCircuitAfterConfiguredFailureAndReportsOpenState() {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowSize(1)
                .minimumNumberOfCalls(1)
                .failureRateThreshold(1)
                .waitDurationInOpenState(Duration.ofMillis(1))
                .build();
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.of(config);
        CircuitBreakerService service = new CircuitBreakerService(registry);

        service.recordFailure("downstream", 9, new IllegalStateException("down"));

        Assertions.assertThat(service.isOpen("downstream")).isTrue();
    }
}
