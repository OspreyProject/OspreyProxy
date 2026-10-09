/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.updates;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

class UpdateCatalogTest {

    private static final Release OLD = new Release("1.9.0", "old.crx", null, null, null, null, null);
    private static final Release NEW = new Release("2.0.0", "new.crx", null, null, null, null, null);

    @Test
    void emptyCatalogHasNoResolution() {
        UpdateCatalog catalog = UpdateCatalog.empty();

        Assertions.assertThat(catalog.appId()).isEmpty();
        Assertions.assertThat(catalog.releases()).isEmpty();
        Assertions.assertThat(catalog.channelPins()).isEmpty();
        Assertions.assertThat(catalog.resolve(null)).isNull();
        Assertions.assertThat(catalog.resolve(" ")).isNull();
        Assertions.assertThat(catalog.resolve("stable")).isNull();
        Assertions.assertThat(catalog.byCrx(null)).isNull();
        Assertions.assertThat(catalog.byCrx("missing.crx")).isNull();
    }

    @Test
    void resolveSupportsCaseInsensitiveChannelsLatestAndFixedPins() {
        UpdateCatalog catalog = new UpdateCatalog("app", List.of(NEW, OLD),
                Map.of("stable", "LATEST", "rollback", "1.9.0", "missing", "0.0.0"));

        Assertions.assertThat(catalog.resolve("STABLE")).isSameAs(NEW);
        Assertions.assertThat(catalog.resolve("rollback")).isSameAs(OLD);
        Assertions.assertThat(catalog.resolve("missing")).isNull();
        Assertions.assertThat(catalog.byCrx("new.crx")).isSameAs(NEW);
        Assertions.assertThat(catalog.byCrx("old.crx")).isSameAs(OLD);
    }

    @Test
    void latestPinDoesNotResolveWhenNoReleasesExist() {
        UpdateCatalog catalog = new UpdateCatalog("app", List.of(), Map.of("stable", "latest"));

        Assertions.assertThat(catalog.resolve("stable")).isNull();
    }

    @Test
    void compareVersionsUsesNumericTrailingZeroAndLexicalFallbackRules() {
        Assertions.assertThat(UpdateCatalog.compareVersions("2.0.10", "2.0.9")).isPositive();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.2", "1.2.0")).isZero();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.2.0", "1.2")).isZero();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.a", "1.10")).isPositive();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.a", "1.b")).isNegative();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.-1", "1.0")).isPositive();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.999999999999999999999", "1.2")).isPositive();
        Assertions.assertThat(UpdateCatalog.compareVersions("3.0", "3.0")).isZero();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.2", "1.a")).isNegative();
        Assertions.assertThat(UpdateCatalog.compareVersions("1.0.2", "1.0.10")).isNegative();
    }

    @Test
    void compareVersionsIsTransitiveForMixedNumericAndNonNumericSegments() {
        List<String> versions = new ArrayList<>(List.of("1.0.a", "1.0.5", "1.0.10", "1.0.b", "1.0.9z", "1.0.0", "1.0"));

        for (String a : versions) {
            for (String b : versions) {
                for (String c : versions) {
                    if (UpdateCatalog.compareVersions(a, b) <= 0 && UpdateCatalog.compareVersions(b, c) <= 0) {
                        Assertions.assertThat(UpdateCatalog.compareVersions(a, c)).isLessThanOrEqualTo(0);
                    }
                }
            }
        }

        for (int i = 0; i < 50; i++) {
            Collections.shuffle(versions);
            Assertions.assertThatCode(() -> versions.sort(UpdateCatalog::compareVersions)).doesNotThrowAnyException();
        }
    }
}
