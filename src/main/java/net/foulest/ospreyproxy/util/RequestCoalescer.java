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

import org.jspecify.annotations.NonNull;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Collapses concurrent duplicate operations that share the same key into a single execution.
 *
 * @param <T> The result type produced by the coalesced operation.
 */
public final class RequestCoalescer<T> {

    // Keyed by coalescing key; holds the leader's future while a computation is in flight
    private final ConcurrentHashMap<String, CompletableFuture<T>> inFlight = new ConcurrentHashMap<>();

    /**
     * Returns the result for {@code key}, running {@code loader} at most once across all callers that
     * overlap in time. If a computation for {@code key} is already in flight, this blocks until it
     * completes and returns its result (or rethrows its failure) instead of running {@code loader}.
     *
     * @param key The coalescing key. Callers sharing a key share a single execution.
     * @param loader The operation to run if this caller is the leader for {@code key}.
     * @return The value produced by the leader's {@code loader} invocation.
     */
    public @NonNull T get(@NonNull String key, @NonNull Supplier<T> loader) {
        CompletableFuture<T> ours = new CompletableFuture<>();
        CompletableFuture<T> leader = inFlight.putIfAbsent(key, ours);

        // A computation for this key is already running; wait for and share its result
        if (leader != null) {
            try {
                return leader.join();
            } catch (CompletionException e) {
                Throwable cause = e.getCause();

                if (cause instanceof RuntimeException runtime) {
                    throw runtime;
                }

                if (cause instanceof Error error) {
                    throw error;
                }
                throw e;
            }
        }

        // We are the leader for this key: compute once, publish to any followers, then release the slot
        try {
            T value = loader.get();
            ours.complete(value);
            return value;
        } catch (Exception e) {
            ours.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(key, ours);
        }
    }
}
