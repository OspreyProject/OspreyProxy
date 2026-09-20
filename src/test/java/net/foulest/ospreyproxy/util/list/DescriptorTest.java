/*
 * Copyright (C) 2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util.list;

import net.foulest.ospreyproxy.result.LookupResult;
import org.junit.jupiter.api.Test;
import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DescriptorTest {

    @Test
    void descriptorMetadataMatchesTheConfiguredFeeds() {
        assertThat(Descriptor.values())
                .extracting(Descriptor::getEndpointName)
                .containsExactlyInAnyOrder(
                        "aa419", "acomics", "openphish", "phishunt-io", "red-flag-domains",
                        "sinking-yachts", "threatfox", "urlhaus", "validin"
                );
        assertThat(Descriptor.AA419.getFormat()).isEqualTo(Format.JSON);
        assertThat(Descriptor.AA419.getShortName()).isEqualTo("AA419");
        assertThat(Descriptor.AA419.getResultType()).isEqualTo(LookupResult.MALICIOUS);
        assertThat(Descriptor.AA419.getRefreshIntervalSeconds()).isEqualTo(300L);
        assertThat(Descriptor.AA419.isAccumulate()).isTrue();
        assertThat(Descriptor.AA419.getAuthHeaderName()).isEqualTo("Auth-API-Id");
        assertThat(Descriptor.AA419.getJsonObjectField()).isEqualTo("Url");
        assertThat(Descriptor.AA419.isGithubApi()).isFalse();
        assertThat(Descriptor.VALIDIN.getUrls()).hasSize(8);
        assertThat(Descriptor.OPEN_PHISH.getFormat()).isEqualTo(Format.TEXT);
        assertThat(Descriptor.OPEN_PHISH.isGithubApi()).isTrue();
        assertThat(Descriptor.OPEN_PHISH.isAccumulate()).isFalse();
        assertThat(Descriptor.THREATFOX.getApiKeyEnvVar()).isEqualTo("THREATFOX_API_KEY");
    }

    @Test
    void submissionFeedHasNoRemoteSourceAndAccumulates() {
        assertThat(Descriptor.ACOMICS.isSubmissionFeed()).isTrue();
        assertThat(Descriptor.ACOMICS.getUrls()).isEmpty();
        assertThat(Descriptor.ACOMICS.getResolvedUrls()).isEmpty();
        assertThat(Descriptor.ACOMICS.getFormat()).isEqualTo(Format.TEXT);
        assertThat(Descriptor.ACOMICS.getRefreshIntervalSeconds()).isZero();
        assertThat(Descriptor.ACOMICS.isAccumulate()).isTrue();
        assertThat(Descriptor.ACOMICS.getApiKeyEnvVar()).isNull();
        assertThat(Descriptor.ACOMICS.isGithubApi()).isFalse();
    }

    @Test
    void descriptorsWithoutKeysReturnIndependentResolvedUrlCopies() {
        List<String> resolved = Descriptor.PHISHUNT_IO.getResolvedUrls();

        assertThat(resolved).containsExactly("https://phishunt.io/feed.txt");
        resolved.add("https://local.test/extra");

        assertThat(Descriptor.PHISHUNT_IO.getResolvedUrls())
                .containsExactly("https://phishunt.io/feed.txt");
        assertThat(Descriptor.PHISHUNT_IO.isSubmissionFeed()).isFalse();
    }

    @Test
    void keyDependentDescriptorsReflectTheActualProcessEnvironment() {
        assertThat(Descriptor.AA419.getResolvedUrls())
                .isEqualTo(expectedResolvedUrls(Descriptor.AA419));
        assertThat(Descriptor.THREATFOX.getResolvedUrls())
                .isEqualTo(expectedResolvedUrls(Descriptor.THREATFOX));
        assertThat(Descriptor.AA419.getAuthHeaderValue())
                .isEqualTo(expectedHeaderValue(Descriptor.AA419));
    }

    @Test
    void configuredKeyResolvesUrlsAndAuthenticationHeader() {
        Map.Entry<String, String> environment = System.getenv().entrySet().stream()
                .filter(entry -> !entry.getValue().isBlank())
                .findFirst()
                .orElseThrow();
        String originalAa419KeyVariable = instanceField(Descriptor.AA419, "apiKeyEnvVar");
        String originalThreatfoxKeyVariable = instanceField(Descriptor.THREATFOX, "apiKeyEnvVar");

        try {
            setInstanceField(Descriptor.AA419, "apiKeyEnvVar", environment.getKey());
            setInstanceField(Descriptor.THREATFOX, "apiKeyEnvVar", environment.getKey());

            assertThat(Descriptor.AA419.getAuthHeaderValue()).isEqualTo(environment.getValue());
            assertThat(Descriptor.THREATFOX.getResolvedUrls())
                    .containsExactly("https://threatfox-api.abuse.ch/v2/files/exports/"
                            + environment.getValue() + "/hostfile.txt");
        } finally {
            setInstanceField(Descriptor.AA419, "apiKeyEnvVar", originalAa419KeyVariable);
            setInstanceField(Descriptor.THREATFOX, "apiKeyEnvVar", originalThreatfoxKeyVariable);
        }
    }

    @Test
    void descriptorsWithoutAuthenticationConfigurationHaveNoHeaderValue() {
        assertThat(Descriptor.OPEN_PHISH.getAuthHeaderValue()).isNull();
    }

    @Test
    void missingAndBlankKeyConfigurationSuppressesAuthenticationAndFetches() {
        String blankKeyVariable = "OSPREYPROXY_DESCRIPTOR_BLANK_KEY_TEST";
        Map<String, String> environment = mutableEnvironment();
        Map<String, String> caseInsensitiveEnvironment = caseInsensitiveEnvironment();
        String originalBlankKeyValue = environment.put(blankKeyVariable, " ");
        String originalCaseInsensitiveBlankKeyValue =
                caseInsensitiveEnvironment.put(blankKeyVariable, " ");
        String originalAa419KeyVariable = instanceField(Descriptor.AA419, "apiKeyEnvVar");
        String originalThreatfoxKeyVariable = instanceField(Descriptor.THREATFOX, "apiKeyEnvVar");

        try {
            setInstanceField(Descriptor.AA419, "apiKeyEnvVar", null);
            assertThat(Descriptor.AA419.getAuthHeaderValue()).isNull();

            setInstanceField(Descriptor.AA419, "apiKeyEnvVar", blankKeyVariable);
            setInstanceField(Descriptor.THREATFOX, "apiKeyEnvVar", blankKeyVariable);

            assertThat(Descriptor.AA419.getAuthHeaderValue()).isNull();
            assertThat(Descriptor.THREATFOX.getResolvedUrls()).isEmpty();
        } finally {
            setInstanceField(Descriptor.AA419, "apiKeyEnvVar", originalAa419KeyVariable);
            setInstanceField(Descriptor.THREATFOX, "apiKeyEnvVar", originalThreatfoxKeyVariable);

            if (originalBlankKeyValue == null) {
                environment.remove(blankKeyVariable);
            } else {
                environment.put(blankKeyVariable, originalBlankKeyValue);
            }

            if (originalCaseInsensitiveBlankKeyValue == null) {
                caseInsensitiveEnvironment.remove(blankKeyVariable);
            } else {
                caseInsensitiveEnvironment.put(blankKeyVariable, originalCaseInsensitiveBlankKeyValue);
            }
        }
    }

    private static List<String> expectedResolvedUrls(Descriptor descriptor) {
        String key = System.getenv(descriptor.getApiKeyEnvVar());

        if (key == null || key.isBlank()) {
            return List.of();
        }
        return descriptor.getUrls().stream()
                .map(url -> url.replace("%api_key%", key))
                .toList();
    }

    private static String expectedHeaderValue(Descriptor descriptor) {
        String key = System.getenv(descriptor.getApiKeyEnvVar());
        return key == null || key.isBlank() || descriptor.getAuthHeaderName() == null ? null : key;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> mutableEnvironment() {
        try {
            Map<String, String> environment = System.getenv();
            Field field = environment.getClass().getDeclaredField("m");
            return (Map<String, String>) UNSAFE.getObject(environment, UNSAFE.objectFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not access the process environment", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> caseInsensitiveEnvironment() {
        try {
            Class<?> processEnvironment = Class.forName("java.lang.ProcessEnvironment");
            Field field = processEnvironment.getDeclaredField("theCaseInsensitiveEnvironment");
            return (Map<String, String>) UNSAFE.getObject(UNSAFE.staticFieldBase(field),
                    UNSAFE.staticFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not access the case-insensitive process environment", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T instanceField(Descriptor descriptor, String name) {
        try {
            Field field = Descriptor.class.getDeclaredField(name);
            field.setAccessible(true);
            return (T) UNSAFE.getObject(descriptor, UNSAFE.objectFieldOffset(field));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not read Descriptor." + name, e);
        }
    }

    private static void setInstanceField(Descriptor descriptor, String name, Object value) {
        try {
            Field field = Descriptor.class.getDeclaredField(name);
            field.setAccessible(true);
            UNSAFE.putObject(descriptor, UNSAFE.objectFieldOffset(field), value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not set Descriptor." + name, e);
        }
    }

    private static final Unsafe UNSAFE = unsafe();

    private static Unsafe unsafe() {
        try {
            Field field = Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            return (Unsafe) field.get(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Could not obtain Unsafe", e);
        }
    }
}
