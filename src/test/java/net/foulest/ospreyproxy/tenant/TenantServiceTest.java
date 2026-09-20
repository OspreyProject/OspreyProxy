/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.tenant;

import jakarta.servlet.ServletRequest;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;

class TenantServiceTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void disabledAndUnconfiguredServicesRejectKeysWithoutFilesystemAccess() {
        TenantService disabled = service(false, "");
        TenantService unconfigured = service(true, "");

        disabled.init();
        unconfigured.init();

        Assertions.assertThat(disabled.isEnabled()).isFalse();
        Assertions.assertThat(unconfigured.isEnabled()).isTrue();
        Assertions.assertThat(disabled.getHeaderName()).isEqualTo("X-Tenant");
        Assertions.assertThat(disabled.resolve(null)).isNull();
        Assertions.assertThat(disabled.resolve("  ")).isNull();
        Assertions.assertThat(disabled.resolve("unknown")).isNull();
        Assertions.assertThat(unconfigured.resolve("unknown")).isNull();
    }

    @Test
    void loadsKeysAndRateOverridesAndRejectsUnknownKeys() throws Exception {
        Path store = temporaryDirectory.resolve("tenants.properties");
        Files.writeString(store, """
                ignored=value
                tenant.alpha.keys= alpha-key, , second-key
                tenant.alpha.rate.burst-capacity=2
                tenant.alpha.rate.burst-window-seconds=3
                tenant.alpha.rate.sustained-capacity=4
                tenant.alpha.rate.sustained-window-seconds=5
                tenant.beta.keys= alpha-key
                tenant.gamma.unknown=value
                tenant.delta.keys=
                """);
        TenantService service = service(true, store.toString());

        service.init();

        Tenant alpha = service.resolve(" alpha-key ");
        Assertions.assertThat(alpha).isNotNull();
        Assertions.assertThat(alpha.id()).isEqualTo("alpha");
        Assertions.assertThat(alpha.rate).isEqualTo(new RateSettings(2, 3, 4, 5));
        Assertions.assertThat(service.resolve("second-key")).isSameAs(alpha);
        Assertions.assertThat(service.resolve("missing")).isNull();
        Assertions.assertThat(service.resolve("alpha-key").tryConsume()).isTrue();
    }

    @Test
    void invalidRateValuesFallBackToConfiguredDefaults() throws Exception {
        Path store = temporaryDirectory.resolve("tenants.properties");
        Files.writeString(store, """
                tenant.alpha.keys=key
                tenant.alpha.rate.burst-capacity=0
                tenant.alpha.rate.burst-window-seconds=-2
                tenant.alpha.rate.sustained-capacity=nope
                tenant.alpha.rate.sustained-window-seconds= 7
                """);
        TenantService service = service(true, store.toString());
        service.init();

        Assertions.assertThat(service.resolve("key").rate).isEqualTo(new RateSettings(11, 1, 400, 7));
    }

    @Test
    void parsesIgnoredFieldsCollisionsAndReloadsTenantChanges() throws Exception {
        Path store = temporaryDirectory.resolve("tenants.properties");
        Files.writeString(store, """
                tenant.invalid=value
                tenant.alpha.keys=alpha,alpha,shared
                tenant.alpha.rate.unknown=value
                tenant.beta.keys=shared,beta
                """);
        TenantService service = service(true, store.toString());

        service.init();

        forceReloadCheck(service);
        Tenant alpha = service.resolve("alpha");
        Assertions.assertThat(alpha).isNotNull();
        Assertions.assertThat(service.resolve("beta")).isNotNull();

        reloadAfterChanging(store, service, """
                tenant.alpha.keys=alpha
                tenant.beta.keys=beta
                """);
        Assertions.assertThat(service.resolve("alpha")).isSameAs(alpha);

        reloadAfterChanging(store, service, """
                tenant.beta.keys=beta
                tenant.gamma.keys=gamma
                """);
        Assertions.assertThat(service.resolve("alpha")).isNull();
        Assertions.assertThat(service.resolve("beta")).isNotNull();
        Assertions.assertThat(service.resolve("gamma")).isNotNull();

        reloadAfterChanging(store, service, """
                tenant.beta.keys=beta
                tenant.gamma.keys=gamma
                """);
        Assertions.assertThat(service.resolve("beta")).isNotNull();
    }

    @Test
    void reloadRebuildsChangedRatesAndRemovesOnlyRevokedTenants() throws Exception {
        Path store = temporaryDirectory.resolve("rate-change.properties");
        Files.writeString(store, """
                tenant.alpha.keys=alpha
                tenant.beta.keys=beta
                """);
        TenantService service = service(true, store.toString());
        service.init();
        Tenant originalBeta = service.resolve("beta");

        reloadAfterChanging(store, service, """
                tenant.beta.keys=beta
                tenant.beta.rate.burst-capacity=2
                """);

        Tenant rebuiltBeta = service.resolve("beta");
        Assertions.assertThat(service.resolve("alpha")).isNull();
        Assertions.assertThat(rebuiltBeta)
                .isNotNull()
                .isNotSameAs(originalBeta)
                .extracting(tenant -> tenant.rate)
                .isEqualTo(new RateSettings(2, 1, 400, 60));
    }

    @Test
    void emptyStoreLoadsNoTenants() throws Exception {
        Path store = temporaryDirectory.resolve("empty.properties");
        Files.writeString(store, "");
        TenantService service = service(true, store.toString());

        service.init();

        Assertions.assertThat(service.resolve("unknown")).isNull();
    }

    @Test
    void concurrentStaleChecksAllowOnlyTheFirstCallerToReload() throws Exception {
        Path store = temporaryDirectory.resolve("concurrent.properties");
        Files.writeString(store, "tenant.alpha.keys=alpha");
        TenantService service = service(true, store.toString());
        service.init();
        Files.writeString(store, "tenant.beta.keys=beta");
        Files.setLastModifiedTime(store, FileTime.fromMillis(System.currentTimeMillis() + 10_000));

        Object reloadLock = privateField(service, "reloadLock");
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread first = resolveThread(service, failure);
        Thread second = resolveThread(service, failure);

        synchronized (reloadLock) {
            forceReloadCheck(service);
            first.start();
            awaitBlocked(first);
            forceReloadCheck(service);
            second.start();
            awaitBlocked(second);
        }

        first.join();
        second.join();

        Assertions.assertThat(failure.get()).isNull();
        Assertions.assertThat(service.resolve("alpha")).isNull();
        Assertions.assertThat(service.resolve("beta")).isNotNull();
    }

    @Test
    void tenantOfUsesOnlyNonEmptyStringAttributes() {
        ServletRequest request = Mockito.mock(ServletRequest.class);

        Mockito.when(request.getAttribute(TenantService.TENANT_ATTRIBUTE)).thenReturn(null);
        Assertions.assertThat(TenantService.tenantOf(request)).isEqualTo(TenantService.ANONYMOUS);
        Mockito.when(request.getAttribute(TenantService.TENANT_ATTRIBUTE)).thenReturn("");
        Assertions.assertThat(TenantService.tenantOf(request)).isEqualTo(TenantService.ANONYMOUS);
        Mockito.when(request.getAttribute(TenantService.TENANT_ATTRIBUTE)).thenReturn(42);
        Assertions.assertThat(TenantService.tenantOf(request)).isEqualTo(TenantService.ANONYMOUS);
        Mockito.when(request.getAttribute(TenantService.TENANT_ATTRIBUTE)).thenReturn("alpha");
        Assertions.assertThat(TenantService.tenantOf(request)).isEqualTo("alpha");
    }

    @Test
    void initSurvivesAnUnreadableStoreFile() {
        Path missing = temporaryDirectory.resolve("absent.properties");
        TenantService service = failureService(missing.toString());

        service.init();

        Assertions.assertThat(service.resolve("anything")).isNull();
    }

    @Test
    void statFailuresKeepTheLastKnownGoodTenantSet() throws IOException {
        Path store = temporaryDirectory.resolve("tenants-failure.properties");
        Files.writeString(store, "tenant.acme.keys=secret-key\n");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.getLastModifiedTime(ArgumentMatchers.any(Path.class)))
                    .thenThrow(new IOException("stat failed"));

            TenantService service = failureService(store.toString());
            service.init();
            Tenant tenant = service.resolve("secret-key");
            Assertions.assertThat(tenant).isNotNull();
            Assertions.assertThat(tenant.id()).isEqualTo("acme");
            Assertions.assertThat(service.resolve("secret-key")).isNotNull();
            Assertions.assertThat(service.resolve("unknown-key")).isNull();
        }
    }

    @Test
    void resolveFailsLoudlyWhenTheDigestAlgorithmIsMissing() {
        TenantService service = failureService("");

        try (MockedStatic<MessageDigest> digests = Mockito.mockStatic(MessageDigest.class)) {
            digests.when(() -> MessageDigest.getInstance("SHA-256"))
                    .thenThrow(new NoSuchAlgorithmException("absent"));

            Assertions.assertThatThrownBy(() -> service.resolve("presented-key"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("SHA-256")
                    .hasCauseInstanceOf(NoSuchAlgorithmException.class);
        }
    }

    private static TenantService failureService(String storePath) {
        return new TenantService(true, "X-Osprey-Tenant-Key", storePath, 11L, 1L, 400L, 60L);
    }

    private static TenantService service(boolean enabled, String path) {
        return new TenantService(enabled, "X-Tenant", path, 11, 1, 400, 60);
    }

    private static void reloadAfterChanging(Path store, TenantService service, String content) throws Exception {
        long nextModifiedMillis = Math.max(System.currentTimeMillis(),
                Files.getLastModifiedTime(store).toMillis()) + 1_000;
        Files.writeString(store, content);
        Files.setLastModifiedTime(store, FileTime.fromMillis(nextModifiedMillis));
        var field = TenantService.class.getDeclaredField("lastStatNanos");
        field.setAccessible(true);
        field.setLong(service, System.nanoTime() - 2_000_000_000L);
        Assertions.assertThat(service.resolve("beta")).isNotNull();
    }

    private static void forceReloadCheck(TenantService service) throws Exception {
        var field = TenantService.class.getDeclaredField("lastStatNanos");
        field.setAccessible(true);
        field.setLong(service, System.nanoTime() - 2_000_000_000L);
    }

    private static Object privateField(TenantService service, String name) throws Exception {
        var field = TenantService.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(service);
    }

    private static Thread resolveThread(TenantService service, AtomicReference<Throwable> failure) {
        return new Thread(() -> {
            try {
                service.resolve("beta");
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
