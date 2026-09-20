/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.updates;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicReference;

class UpdateServiceTest {

    @TempDir
    Path updatesDirectory;

    @Test
    void missingCatalogUsesStableLatestDefaultAndConfiguredAppId() {
        UpdateService service = new UpdateService(updatesDirectory.toString(), "https://updates.example/", "configured");

        service.init();

        Assertions.assertThat(service.getBaseUrl()).isEqualTo("https://updates.example");
        Assertions.assertThat(service.catalog().channelPins()).containsEntry("stable", "latest");
        Assertions.assertThat(service.resolve("stable")).isNull();
        Assertions.assertThat(service.effectiveAppId(null)).isEqualTo("configured");
        Assertions.assertThat(service.effectiveAppId("request")).isEqualTo("configured");
    }

    @Test
    void parsesSortsAndResolvesCatalogEntriesWhileSkippingInvalidOnes() throws Exception {
        Files.writeString(updatesDirectory.resolve("releases.json"), """
                {"app_id":" document-app ","releases":[
                  {"version":"2.0.9","crx":" old.crx ","notes":"old"},
                  {"version":"2.0.10","crx":"new.crx","date":"2026-01-01"},
                  {"version":"","crx":"invalid.crx"},
                  "invalid"
                ]}
                """);
        Files.writeString(updatesDirectory.resolve("channels.json"), """
                {"channels":{"Stable":"latest","rollback":{"version":"2.0.9"},
                "empty":"","bad":3," ":"latest"}}
                """);
        UpdateService service = new UpdateService(updatesDirectory.toString(), "", "");

        service.init();

        Assertions.assertThat(service.effectiveAppId(null)).isEqualTo("");
        Assertions.assertThat(service.catalog().appId()).isEqualTo("document-app");
        Assertions.assertThat(service.catalog().releases()).extracting(Release::version)
                .containsExactly("2.0.10", "2.0.9");
        Assertions.assertThat(service.resolve("stable").version()).isEqualTo("2.0.10");
        Assertions.assertThat(service.resolve("rollback").crx()).isEqualTo("old.crx");
    }

    @Test
    void validatesCrxPathsAndCachesMetadataByFileIdentity() throws Exception {
        Path crx = updatesDirectory.resolve("package.crx");
        Files.write(crx, new byte[]{1, 2, 3});
        UpdateService service = new UpdateService(updatesDirectory.toString(), "", "");

        Assertions.assertThat(service.crxPath("package.crx")).isEqualTo(crx);
        Assertions.assertThat(service.crxPath("missing.crx")).isNull();
        Assertions.assertThat(service.crxPath("../outside.crx")).isNull();
        CRXMeta first = service.crxMeta("package.crx");
        CRXMeta cached = service.crxMeta("package.crx");
        Assertions.assertThat(first).isNotNull();
        Assertions.assertThat(cached).isSameAs(first);
        Assertions.assertThat(first.size()).isEqualTo(3);
        Assertions.assertThat(first.sha256()).hasSize(64);
    }

    @Test
    void reloadsChangedCatalogsAndRecomputesChangedCrxMetadata() throws Exception {
        Path releases = updatesDirectory.resolve("releases.json");
        Path crx = updatesDirectory.resolve("package.crx");
        Files.writeString(releases, """
                {"releases":[{"version":"1.0.0","crx":"package.crx"}]}
                """);
        Files.write(crx, new byte[]{1});
        UpdateService service = new UpdateService(updatesDirectory.toString(), "https://plain.example", "");

        service.init();

        Assertions.assertThat(service.effectiveAppId("requested")).isEqualTo("requested");
        Assertions.assertThat(service.getBaseUrl()).isEqualTo("https://plain.example");
        CRXMeta original = service.crxMeta("package.crx");
        Assertions.assertThat(service.crxMeta("missing.crx")).isNull();

        Files.writeString(releases, """
                {"app_id":4,"releases":[{"version":"2.0.0","crx":"package.crx"}]}
                """);
        Files.setLastModifiedTime(releases, FileTime.fromMillis(System.currentTimeMillis() + 10_000));
        setLastStatNanos(service, System.nanoTime() - 2_000_000_000L);

        Assertions.assertThat(service.catalog().releases()).extracting(Release::version).containsExactly("2.0.0");

        setLastStatNanos(service, System.nanoTime() - 2_000_000_000L);
        service.catalog();
        Files.write(crx, new byte[]{1, 2});

        CRXMeta resized = service.crxMeta("package.crx");
        Files.setLastModifiedTime(crx, FileTime.fromMillis(resized.modifiedMillis() + 1_000));

        Assertions.assertThat(resized).isNotSameAs(original);
        Assertions.assertThat(service.crxMeta("package.crx")).isNotSameAs(resized);

        Files.writeString(updatesDirectory.resolve("channels.json"), """
                {"channels":{"stable":"2.0.0"}}
                """);
        setLastStatNanos(service, System.nanoTime() - 2_000_000_000L);
        Assertions.assertThat(service.resolve("stable").version()).isEqualTo("2.0.0");
    }

    @Test
    void keepsLastGoodCatalogAndSkipsMalformedCatalogEntries() throws Exception {
        Path releases = updatesDirectory.resolve("releases.json");
        Files.writeString(releases, "{not-json");
        UpdateService unreadable = new UpdateService(updatesDirectory.toString(), "", "");

        unreadable.init();

        Assertions.assertThat(unreadable.catalog().releases()).isEmpty();
        Assertions.assertThat(unreadable.catalog().channelPins()).isEmpty();

        Files.writeString(releases, """
                {"app_id":4,"releases":{"version":"not-an-array"}}
                """);
        Files.writeString(updatesDirectory.resolve("channels.json"), """
                {"channels":{"empty-object":{},"blank-object":{"version":" "}}}
                """);
        UpdateService nonList = new UpdateService(updatesDirectory.toString(), "", "");

        nonList.init();

        Assertions.assertThat(nonList.catalog().releases()).isEmpty();
        Assertions.assertThat(nonList.catalog().channelPins()).containsEntry("stable", "latest");

        Files.writeString(releases, """
                {"releases":[{"crx":"missing-version.crx"},{"version":"missing-crx"},
                {"version":"blank-crx","crx":" "}]}
                """);
        UpdateService invalidEntries = new UpdateService(updatesDirectory.toString(), "", "");

        invalidEntries.init();

        Assertions.assertThat(invalidEntries.catalog().releases()).isEmpty();

        UpdateService configured = new UpdateService(updatesDirectory.toString(), "", "configured");
        configured.init();

        Assertions.assertThat(configured.catalog().appId()).isEqualTo("configured");
    }

    @Test
    void concurrentStaleChecksAllowOnlyTheFirstCallerToReload() throws Exception {
        Path releases = updatesDirectory.resolve("releases.json");
        Files.writeString(releases, """
                {"releases":[{"version":"1.0.0","crx":"one.crx"}]}
                """);
        UpdateService service = new UpdateService(updatesDirectory.toString(), "", "");
        service.init();
        Files.writeString(releases, """
                {"releases":[{"version":"2.0.0","crx":"two.crx"}]}
                """);
        Files.setLastModifiedTime(releases, FileTime.fromMillis(System.currentTimeMillis() + 10_000));

        Object reloadLock = privateField(service, "reloadLock");
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread first = catalogThread(service, failure);
        Thread second = catalogThread(service, failure);

        // Both callers read stale metadata before the first one can enter the double-check lock.
        synchronized (reloadLock) {
            setLastStatNanos(service, System.nanoTime() - 2_000_000_000L);
            first.start();
            awaitBlocked(first);
            setLastStatNanos(service, System.nanoTime() - 2_000_000_000L);
            second.start();
            awaitBlocked(second);
        }

        first.join();
        second.join();

        Assertions.assertThat(failure.get()).isNull();
        Assertions.assertThat(service.catalog().releases()).extracting(Release::version).containsExactly("2.0.0");
    }

    @Test
    void returnsSafeResultsForCatalogFileFailures() throws Exception {
        Path crx = updatesDirectory.resolve("package.crx");
        Files.writeString(crx, "content");
        UpdateService service = new UpdateService(updatesDirectory.toString(), "", "");
        service.init();

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.size(crx)).thenThrow(new java.io.IOException("unavailable"));
            Assertions.assertThat(service.crxMeta("package.crx")).isNull();
        }
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.readAllBytes(crx)).thenThrow(new java.io.IOException("unavailable"));
            Assertions.assertThat(service.crxMeta("package.crx")).isNull();
        }
    }

    @Test
    void reportsUnavailableDigestAlgorithm() throws Exception {
        Method sha256 = UpdateService.class.getDeclaredMethod("sha256Hex", byte[].class);
        sha256.setAccessible(true);
        try (MockedStatic<MessageDigest> digests = Mockito.mockStatic(MessageDigest.class)) {
            digests.when(() -> MessageDigest.getInstance("SHA-256"))
                    .thenThrow(new java.security.NoSuchAlgorithmException("missing"));
            Assertions.assertThatThrownBy(() -> sha256.invoke(null, new byte[0]))
                    .isInstanceOf(InvocationTargetException.class)
                    .hasCauseInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void treatsUnreadableModificationTimesAsMissing() throws Exception {
        Path file = updatesDirectory.resolve("catalog.json");
        Files.writeString(file, "{}");

        Method lastModified = UpdateService.class.getDeclaredMethod("lastModified", Path.class);
        lastModified.setAccessible(true);

        Assertions.assertThat((long) lastModified.invoke(null, file)).isPositive();
        Assertions.assertThat((long) lastModified.invoke(null, updatesDirectory.resolve("absent.json"))).isEqualTo(-1L);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.getLastModifiedTime(file))
                    .thenThrow(new java.io.IOException("unavailable"));
            Assertions.assertThat((long) lastModified.invoke(null, file)).isEqualTo(-1L);
        }
    }

    private static void setLastStatNanos(UpdateService service, long value) throws Exception {
        var field = UpdateService.class.getDeclaredField("lastStatNanos");
        field.setAccessible(true);
        field.setLong(service, value);
    }

    private static Object privateField(UpdateService service, String name) throws Exception {
        var field = UpdateService.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(service);
    }

    private static Thread catalogThread(UpdateService service, AtomicReference<Throwable> failure) {
        return new Thread(() -> {
            try {
                service.catalog();
            } catch (Throwable throwable) {
                failure.set(throwable);
            }
        });
    }

    private static void awaitBlocked(Thread thread) throws InterruptedException {
        for (int attempt = 0; attempt < 100 && thread.getState() != Thread.State.BLOCKED; attempt++) {
            Thread.sleep(10);
        }
        Assertions.assertThat(thread.getState()).isEqualTo(Thread.State.BLOCKED);
    }
}
