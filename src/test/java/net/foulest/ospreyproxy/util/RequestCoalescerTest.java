/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class RequestCoalescerTest {

    @Test
    void concurrentFollowersShareTheLeaderResultAndInvokeOneLoader() throws Exception {
        RequestCoalescer<String> coalescer = new RequestCoalescer<>();
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch followerStarted = new CountDownLatch(1);
        AtomicReference<Thread> followerThread = new AtomicReference<>();
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            CompletableFuture<String> leader = CompletableFuture.supplyAsync(
                    () -> coalescer.get("key", () -> {
                        calls.incrementAndGet();
                        entered.countDown();
                        await(release);
                        return "value";
                    }),
                    executor
            );
            Assertions.assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            CompletableFuture<String> follower = CompletableFuture.supplyAsync(
                    () -> {
                        followerThread.set(Thread.currentThread());
                        followerStarted.countDown();
                        return coalescer.get("key", () -> {
                            calls.incrementAndGet();
                            return "other";
                        });
                    },
                    executor
            );

            Assertions.assertThat(followerStarted.await(5, TimeUnit.SECONDS)).isTrue();
            awaitWaiting(followerThread.get());
            release.countDown();
            Assertions.assertThat(leader.get(5, TimeUnit.SECONDS)).isEqualTo("value");
            Assertions.assertThat(follower.get(5, TimeUnit.SECONDS)).isEqualTo("value");
            Assertions.assertThat(calls).hasValue(1);
        } finally {
            executor.shutdownNow();
        }
    }

    private static void awaitWaiting(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);

        while (thread.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        Assertions.assertThat(thread.getState()).isEqualTo(Thread.State.WAITING);
    }

    @Test
    void leaderPropagatesRuntimeFailureAndReleasesKeyForLaterCall() {
        RequestCoalescer<String> coalescer = new RequestCoalescer<>();

        Assertions.assertThatThrownBy(() -> coalescer.get("key", () -> {
            throw new IllegalStateException("failure");
        })).isInstanceOf(IllegalStateException.class).hasMessage("failure");
        Assertions.assertThat(coalescer.get("key", () -> "recovered")).isEqualTo("recovered");
    }

    @Test
    void followerRethrowsRuntimeAndErrorCausesAndWrapsCheckedCause() throws Exception {
        RequestCoalescer<String> coalescer = new RequestCoalescer<>();

        futureFor(coalescer, "runtime").completeExceptionally(new IllegalArgumentException("runtime"));
        Assertions.assertThatThrownBy(() -> coalescer.get("runtime", () -> "unused"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("runtime");

        futureFor(coalescer, "error").completeExceptionally(new AssertionError("error"));
        Assertions.assertThatThrownBy(() -> coalescer.get("error", () -> "unused"))
                .isInstanceOf(AssertionError.class).hasMessage("error");

        futureFor(coalescer, "checked").completeExceptionally(new Exception("checked"));
        Assertions.assertThatThrownBy(() -> coalescer.get("checked", () -> "unused"))
                .isInstanceOf(java.util.concurrent.CompletionException.class)
                .hasCauseInstanceOf(Exception.class);
    }

    @SuppressWarnings("unchecked")
    private static CompletableFuture<String> futureFor(RequestCoalescer<String> coalescer, String key) throws Exception {
        Field field = RequestCoalescer.class.getDeclaredField("inFlight");
        field.setAccessible(true);
        ConcurrentHashMap<String, CompletableFuture<String>> inFlight =
                (ConcurrentHashMap<String, CompletableFuture<String>>) field.get(coalescer);
        CompletableFuture<String> future = new CompletableFuture<>();
        inFlight.put(key, future);
        return future;
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("Timed out waiting for coalesced request");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }
}
