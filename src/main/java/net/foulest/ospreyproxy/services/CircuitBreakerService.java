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
package net.foulest.ospreyproxy.services;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Circuit-breaker service for upstream API providers.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CircuitBreakerService {

    private final CircuitBreakerRegistry registry;

    /**
     * Check if the circuit breaker for the given provider is currently open, which indicates that the provider
     * is experiencing issues and calls to it should be avoided until it recovers.
     *
     * @param providerName The unique name of the provider (e.g. "cloudflare-security").
     * @return true if the circuit breaker for the provider is open, false otherwise.
     */
    public boolean isOpen(@NonNull String providerName) {
        return circuitBreaker(providerName).getState() == CircuitBreaker.State.OPEN;
    }

    /**
     * Record a successful call for the given provider, which will help the circuit breaker track the success rate and
     * potentially close the circuit if it was previously open.
     *
     * @param providerName The unique name of the provider (e.g. "cloudflare-security").
     * @param durationNanos The duration of the successful call in nanoseconds, used for metrics and circuit breaker calculations.
     */
    public void recordSuccess(@NonNull String providerName, long durationNanos) {
        circuitBreaker(providerName).onSuccess(durationNanos, TimeUnit.NANOSECONDS);
    }

    /**
     * Record a failure for the given provider, which may trigger the circuit breaker to open if the failure rate
     * exceeds the configured threshold.
     *
     * @param providerName The unique name of the provider (e.g. "cloudflare-security").
     * @param durationNanos The duration of the failed call in nanoseconds, used for metrics and circuit breaker calculations.
     * @param throwable The exception that caused the failure, which will be recorded by the circuit breaker for monitoring and debugging purposes.
     */
    public void recordFailure(@NonNull String providerName, long durationNanos,
                              @NonNull Throwable throwable) {
        circuitBreaker(providerName).onError(durationNanos, TimeUnit.NANOSECONDS, throwable);
    }

    /**
     * Get or create a circuit breaker for the given provider name.
     *
     * @param providerName The unique name of the provider (e.g. "cloudflare-security").
     * @return The circuit breaker instance for the provider.
     */
    private @NonNull CircuitBreaker circuitBreaker(@NonNull String providerName) {
        // Lazily create circuit breaker if it doesn't exist
        CircuitBreaker cb = registry.circuitBreaker(providerName);

        // Log state transitions for debugging
        cb.getEventPublisher().onStateTransition(event -> {
            CircuitBreaker.StateTransition stateTransition = event.getStateTransition();
            CircuitBreaker.State toState = stateTransition.getToState();
            CircuitBreaker.State fromState = stateTransition.getFromState();
            log.warn("[{}] Circuit breaker state: {} → {}", providerName, fromState, toState);
        });
        return cb;
    }
}
