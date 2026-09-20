/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.result;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

class LookupVerdictTest {

    @Test
    void ofSingleSpecialResultsReusesSharedSingletons() {
        Assertions.assertThat(LookupVerdict.of(LookupResult.FAILED)).isSameAs(LookupVerdict.FAILED);
        Assertions.assertThat(LookupVerdict.of(LookupResult.RATE_LIMITED)).isSameAs(LookupVerdict.RATE_LIMITED);
        Assertions.assertThat(LookupVerdict.of(LookupResult.ALLOWED)).isSameAs(LookupVerdict.ALLOWED);
    }

    @Test
    void ofSingleOrdinaryResultCreatesSingleResultVerdict() {
        LookupVerdict verdict = LookupVerdict.of(LookupResult.MALICIOUS);

        Assertions.assertThat(verdict.results()).containsExactly(LookupResult.MALICIOUS);
        Assertions.assertThat(verdict).isNotSameAs(LookupVerdict.of(LookupResult.MALICIOUS));
    }

    @Test
    void ofNullAndEmptyCollectionsCollapseToFailed() {
        Assertions.assertThat(LookupVerdict.of((List<LookupResult>) null)).isSameAs(LookupVerdict.FAILED);
        Assertions.assertThat(LookupVerdict.of(List.of())).isSameAs(LookupVerdict.FAILED);
    }

    @Test
    void ofCollectionDeduplicatesAndOrdersBySeverityRatherThanEnumOrdinal() {
        LookupVerdict verdict = LookupVerdict.of(List.of(
                LookupResult.ALLOWED,
                LookupResult.MALICIOUS,
                LookupResult.PHISHING,
                LookupResult.MALICIOUS,
                LookupResult.RATE_LIMITED));

        Assertions.assertThat(verdict.results()).containsExactly(
                LookupResult.PHISHING,
                LookupResult.MALICIOUS,
                LookupResult.ALLOWED,
                LookupResult.RATE_LIMITED);
        Assertions.assertThat(verdict.primary()).isEqualTo(LookupResult.PHISHING);
        Assertions.assertThat(verdict.values()).containsExactly(
                "phishing", "malicious", "allowed", "rate_limited");
        Assertions.assertThatThrownBy(() -> verdict.results().add(LookupResult.FAILED))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void ofSingleCollectionDelegatesToSingletonAwareFactory() {
        Assertions.assertThat(LookupVerdict.of(List.of(LookupResult.ALLOWED))).isSameAs(LookupVerdict.ALLOWED);
        Assertions.assertThat(LookupVerdict.of(List.of(LookupResult.SUSPICIOUS)).results())
                .containsExactly(LookupResult.SUSPICIOUS);
    }

    @Test
    void statusPredicatesOnlyMatchTheirExactSingleResult() {
        LookupVerdict mixed = LookupVerdict.of(List.of(LookupResult.ALLOWED, LookupResult.MALICIOUS));

        Assertions.assertThat(LookupVerdict.FAILED.isFailed()).isTrue();
        Assertions.assertThat(LookupVerdict.FAILED.isRateLimited()).isFalse();
        Assertions.assertThat(LookupVerdict.FAILED.isAllowedOnly()).isFalse();
        Assertions.assertThat(LookupVerdict.RATE_LIMITED.isFailed()).isFalse();
        Assertions.assertThat(LookupVerdict.RATE_LIMITED.isRateLimited()).isTrue();
        Assertions.assertThat(LookupVerdict.RATE_LIMITED.isAllowedOnly()).isFalse();
        Assertions.assertThat(LookupVerdict.ALLOWED.isFailed()).isFalse();
        Assertions.assertThat(LookupVerdict.ALLOWED.isRateLimited()).isFalse();
        Assertions.assertThat(LookupVerdict.ALLOWED.isAllowedOnly()).isTrue();
        Assertions.assertThat(mixed.isFailed()).isFalse();
        Assertions.assertThat(mixed.isRateLimited()).isFalse();
        Assertions.assertThat(mixed.isAllowedOnly()).isFalse();
    }

    @Test
    void equalityHashCodeAndStringRepresentEquivalentVerdicts() {
        LookupVerdict first = LookupVerdict.of(List.of(LookupResult.MALICIOUS, LookupResult.SUSPICIOUS));
        LookupVerdict same = LookupVerdict.of(List.of(LookupResult.SUSPICIOUS, LookupResult.MALICIOUS));
        LookupVerdict different = LookupVerdict.of(LookupResult.ALLOWED);

        Assertions.assertThat(first)
                .isEqualTo(first)
                .isEqualTo(same)
                .hasSameHashCodeAs(same)
                .isNotEqualTo(different)
                .isNotEqualTo("not a verdict");
        Assertions.assertThat(first.equals(null)).isFalse();
        Assertions.assertThat(first).hasToString("[LookupVerdict] [MALICIOUS, SUSPICIOUS]");
    }
}
