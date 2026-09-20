/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.store;

import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.util.check.PreparedUrl;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

class ScanAggregatorTest {

    private static final PreparedUrl PREPARED = new PreparedUrl(
            "bad.example", "example", "https://bad.example/path", true);

    @Test
    void rejectsEmptyAndAllUnavailableScans() {
        Assertions.assertThat(ScanAggregator.build(PREPARED, Map.of(), 1)).isNull();
        Assertions.assertThat(ScanAggregator.build(PREPARED, Map.of(
                "failed", LookupVerdict.FAILED,
                "limited", LookupVerdict.RATE_LIMITED), 1)).isNull();
    }

    @Test
    void rejectsWhenStrictMajorityOfProvidersFailed() {
        ScanRecord record = ScanAggregator.build(PREPARED, Map.of(
                "failed-one", LookupVerdict.FAILED,
                "failed-two", LookupVerdict.FAILED,
                "allowed", LookupVerdict.ALLOWED), 10);

        Assertions.assertThat(record).isNull();
    }

    @Test
    void acceptsExactlyHalfFailedWhenThereIsUsableSignalAndPreservesResults() {
        Map<String, LookupVerdict> verdicts = new LinkedHashMap<>();
        verdicts.put("failed", LookupVerdict.FAILED);
        verdicts.put("allowed", LookupVerdict.ALLOWED);
        verdicts.put("limited", LookupVerdict.RATE_LIMITED);
        verdicts.put("suspicious", LookupVerdict.of(LookupResult.SUSPICIOUS));

        ScanRecord record = ScanAggregator.build(PREPARED, verdicts, 123);

        Assertions.assertThat(record)
                .extracting(ScanRecord::canonicalUrl, ScanRecord::host, ScanRecord::bareHost,
                        ScanRecord::primaryResult, ScanRecord::flaggedCount, ScanRecord::totalCount,
                        ScanRecord::firstScannedAt, ScanRecord::lastScannedAt, ScanRecord::scanCount,
                        ScanRecord::indexable, ScanRecord::publishedAt)
                .containsExactly("https://bad.example/path", "bad.example", "example",
                        "suspicious", 1, 4, 123L, 123L, 1, false, null);
        Assertions.assertThat(record.results()).containsEntry("suspicious", java.util.List.of("suspicious"));
    }

    @Test
    void onlyPhishingAndMaliciousPrimaryVerdictsAreIndexable() {
        ScanRecord phishing = ScanAggregator.build(PREPARED, Map.of(
                "allow", LookupVerdict.ALLOWED,
                "phish", LookupVerdict.of(LookupResult.PHISHING)), 1);
        ScanRecord malicious = ScanAggregator.build(PREPARED, Map.of(
                "malware", LookupVerdict.of(LookupResult.MALICIOUS)), 1);

        Assertions.assertThat(phishing).extracting(ScanRecord::primaryResult, ScanRecord::indexable)
                .containsExactly("phishing", true);
        Assertions.assertThat(malicious).extracting(ScanRecord::primaryResult, ScanRecord::indexable)
                .containsExactly("malicious", true);
    }
}
