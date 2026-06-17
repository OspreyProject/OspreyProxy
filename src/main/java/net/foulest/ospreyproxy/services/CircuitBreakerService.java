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
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.core.IntervalFunction;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Circuit-breaker service for upstream API providers.
 */
@Slf4j
@Service
public class CircuitBreakerService {

    // Open-state wait floor and ceiling for the exponential backoff below
    private static final long OPEN_STATE_INITIAL_MILLIS = 30_000L;
    private static final long OPEN_STATE_MAX_MILLIS = 300_000L;
    private static final double OPEN_STATE_MULTIPLIER = 2.0;

    private final CircuitBreakerRegistry registry;
    private final CircuitBreakerConfig tunedConfig;
    private final Set<String> listenersRegistered = ConcurrentHashMap.newKeySet();

    /**
     * Builds the service, deriving a per-provider config from the property-configured default that
     * adds exponential backoff to the open → half-open wait.
     * <p>
     * The wait starts at {@value #OPEN_STATE_INITIAL_MILLIS}ms and doubles on each <em>consecutive</em>
     * open cycle, capped at {@value #OPEN_STATE_MAX_MILLIS}ms. A provider that recovers resets the
     * backoff to the floor; a provider that stays down (e.g. Switch.ch) is probed ever less frequently
     * instead of every 30s, which stops the OPEN ↔ CLOSED sawtooth. Every other setting (sliding
     * window, thresholds, recorded exceptions) is inherited unchanged from the default config.
     *
     * @param registry The Resilience4j registry, autoconfigured from {@code application.properties}.
     */
    public CircuitBreakerService(@NonNull CircuitBreakerRegistry registry) {
        this.registry = registry;

        IntervalFunction openStateBackoff = (Integer attempt) -> {
            double computed = OPEN_STATE_INITIAL_MILLIS * Math.pow(OPEN_STATE_MULTIPLIER, Math.max(0, attempt - 1));
            return (long) Math.min(OPEN_STATE_MAX_MILLIS, computed);
        };

        tunedConfig = CircuitBreakerConfig.from(registry.getDefaultConfig())
                .waitIntervalFunctionInOpenState(openStateBackoff)
                .build();
    }

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
        CircuitBreaker cb = registry.circuitBreaker(providerName, tunedConfig);

        if (listenersRegistered.add(providerName)) {
            cb.getEventPublisher().onStateTransition(event ->
                    log.warn("[{}] Circuit breaker state: {} → {}", providerName,
                            event.getStateTransition().getFromState(),
                            event.getStateTransition().getToState()));
        }
        return cb;
    }
}
