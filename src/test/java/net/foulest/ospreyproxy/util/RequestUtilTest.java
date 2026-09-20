/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util;

import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.Provider;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

class RequestUtilTest {

    private static final String PROVIDER_NAME = "Test";
    private static final String HASHED_IP = "hashed-ip";

    @Test
    void hashClientIpPrefersValidProxyHeaderAndFallsBackForInvalidValues() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Real-IP")).thenReturn(" 2001:DB8::1 ");
        Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                .isEqualTo(HashUtil.hashIp("2001:db8::1"));

        Mockito.when(request.getHeader("X-Real-IP")).thenReturn("not-an-ip");
        Mockito.when(request.getRemoteAddr()).thenReturn(" 192.0.2.9 ");
        Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                .isEqualTo(HashUtil.hashIp("192.0.2.9"));

        Mockito.when(request.getHeader("X-Real-IP")).thenReturn("::ffff:8.8.8.8");
        Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                .isEqualTo(HashUtil.hashIp("::ffff:8.8.8.8"));

        Mockito.when(request.getHeader("X-Real-IP")).thenReturn("1:2:3:4:5:6:7:8:9");
        Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                .isEqualTo(HashUtil.hashIp("192.0.2.9"));

        Mockito.when(request.getHeader("X-Real-IP")).thenReturn(null);
        Mockito.when(request.getRemoteAddr()).thenReturn(null);
        Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                .isEqualTo(HashUtil.hashIp("unknown"));
    }

    @Test
    void hashClientIpRejectsEveryMalformedProxyLiteralShape() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRemoteAddr()).thenReturn("8.8.8.8");

        for (String malformed : new String[]{
                " ", "a".repeat(1_000), "8.8.8.8,1.1.1.1",
                "fe80::1%zone", "[::1]", "::1]", "2001::g", "2001::G", "2001::.g", "2001::_", "2001::/"}) {
            Mockito.when(request.getHeader("X-Real-IP")).thenReturn(malformed);
            Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                    .as("malformed header %s", malformed)
                    .isEqualTo(HashUtil.hashIp("8.8.8.8"));
        }

        Mockito.when(request.getHeader("X-Real-IP")).thenReturn("ABCD:EF01::1");
        Assertions.assertThat(RequestUtil.hashClientIp(request, PROVIDER_NAME))
                .isEqualTo(HashUtil.hashIp("abcd:ef01::1"));
    }

    @Test
    void validateIpUsesAnonymousAndTenantKeysAndRejectsEveryBlockStage() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRemoteAddr()).thenReturn("8.8.8.8");
        Provider provider = unlimitedProvider();
        String expectedHash = HashUtil.hashIp("8.8.8.8");

        Assertions.assertThat(RequestUtil.validateIP(request, provider, PROVIDER_NAME, null)).isEqualTo(expectedHash);
        Assertions.assertThat(RequestUtil.validateIP(request, provider, PROVIDER_NAME, "  ")).isEqualTo(expectedHash);
        Assertions.assertThat(RequestUtil.validateIP(request, provider, PROVIDER_NAME, "tenant"))
                .isEqualTo("tenant\u0000" + expectedHash);

        Provider blocked = Mockito.mock(Provider.class);
        Mockito.when(blocked.isInvalidRequestBlocked(expectedHash)).thenReturn(true);
        assertStatus(429, () -> RequestUtil.validateIP(request, blocked, PROVIDER_NAME, null));

        Provider burstBlocked = Mockito.mock(Provider.class);
        Mockito.when(burstBlocked.isRateLimitingEnabled()).thenReturn(true);
        Mockito.when(burstBlocked.isBurstBlocked(expectedHash)).thenReturn(true);
        assertStatus(429, () -> RequestUtil.validateIP(request, burstBlocked, PROVIDER_NAME, null));

        Provider sustainedBlocked = Mockito.mock(Provider.class);
        Bucket burstBucket = Mockito.mock(Bucket.class);
        Mockito.when(sustainedBlocked.isRateLimitingEnabled()).thenReturn(true);
        Mockito.when(sustainedBlocked.getBurstBucket(expectedHash)).thenReturn(burstBucket);
        Mockito.when(burstBucket.tryConsume(1)).thenReturn(true);
        Mockito.when(sustainedBlocked.isSustainedBlocked(expectedHash)).thenReturn(true);
        assertStatus(429, () -> RequestUtil.validateIP(request, sustainedBlocked, PROVIDER_NAME, null));
    }

    @Test
    void validateBodyAcceptsOnlyOneOptionalStringUrlAndRejectsMalformedShapes() {
        Provider provider = unlimitedProvider();

        Assertions.assertThat(RequestUtil.validateBody("{}".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP)).isEmpty();
        Assertions.assertThat(RequestUtil.validateBody("{\"url\":null}".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP))
                .isEmpty();
        Assertions.assertThat(RequestUtil.validateBody("{\"url\":\"https://example.com\"}".getBytes(StandardCharsets.UTF_8),
                provider, PROVIDER_NAME, HASHED_IP)).isEqualTo(Map.of("url", "https://example.com"));

        assertStatus(400, () -> RequestUtil.validateBody(null, provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody(new byte[0], provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody("[]".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody("{\"other\":\"x\"}".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody("{\"url\":\"x\",\"other\":\"y\"}".getBytes(StandardCharsets.UTF_8),
                provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody("{\"url\":1}".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody("{".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateBody("{}{}".getBytes(StandardCharsets.UTF_8), provider, PROVIDER_NAME, HASHED_IP));
    }

    @Test
    void validateUriCoversBoundarySyntaxNormalizationAndSchemelessInput() {
        Provider provider = unlimitedProvider();

        assertStatus(400, () -> RequestUtil.validateURI(" ", provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateURI("a".repeat(8193), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateURI("http://example.com/\"", provider, PROVIDER_NAME, HASHED_IP));
        URI schemeless = RequestUtil.validateURI("Example.COM/a path", provider, PROVIDER_NAME, HASHED_IP);
        Assertions.assertThat(schemeless)
                .hasScheme("https")
                .hasHost("Example.COM");
        Assertions.assertThat(schemeless.getRawPath()).isEqualTo("/a%20path");
        Assertions.assertThat(RequestUtil.validateURI("HTTP://example.com/a/../b", provider, PROVIDER_NAME, HASHED_IP))
                .hasScheme("HTTP")
                .hasPath("/b");
    }

    @Test
    void validateSchemePermitsHttpAndHttpsOnly() {
        Provider provider = unlimitedProvider();

        Assertions.assertThat(RequestUtil.validateScheme(URI.create("HTTP://example.com"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("http");
        Assertions.assertThat(RequestUtil.validateScheme(URI.create("https://example.com"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("https");
        assertStatus(400, () -> RequestUtil.validateScheme(URI.create("ftp://example.com"), provider,
                PROVIDER_NAME, HASHED_IP));
    }

    @Test
    void validateHostNormalizesValidHostsAndHandlesAddressesAndIdn() throws Exception {
        Provider provider = unlimitedProvider();

        Assertions.assertThat(RequestUtil.validateHost(new URI("http://...Example.COM..."), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("example.com");
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://8.8.8.8"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("8.8.8.8");
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://[2001:db8::1]"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("2001:db8::1");
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://good-1.example"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("good-1.example");
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://b\u00fccher.example"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("xn--bcher-kva.example");
    }

    @Test
    void validateHostRejectsMissingPrivateMalformedAndInvalidLabelValues() throws Exception {
        Provider provider = unlimitedProvider();

        assertStatus(400, () -> RequestUtil.validateHost(new URI("http:/no-authority"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://:8080"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://a"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://..."), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://" + "a".repeat(254) + ".com"),
                provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://" + "a".repeat(64) + ".example"),
                provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://host"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://service.local"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://bad::address"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://-bad.example"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://bad-.example"), provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://user@bad_host.example"), provider,
                PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://bad_.example"), provider,
                PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://example..com"), provider,
                PROVIDER_NAME, HASHED_IP));

        String idnOverlong = String.join(".", "\u00e9".repeat(57), "\u00e9".repeat(57),
                "\u00e9".repeat(57), "\u00e9".repeat(57));
        assertStatus(400, () -> RequestUtil.validateHost(new URI("http://" + idnOverlong), provider,
                PROVIDER_NAME, HASHED_IP));
    }

    @Test
    void registrableDomainHelpersCoverPublicSuffixInvalidAndIpCases() {
        Assertions.assertThat(RequestUtil.hasRegistrableDomain("sub.example.co.uk")).isTrue();
        Assertions.assertThat(RequestUtil.hasRegistrableDomain("co.uk")).isFalse();
        Assertions.assertThat(RequestUtil.hasRegistrableDomain("8.8.8.8")).isFalse();
        Assertions.assertThat(RequestUtil.hasRegistrableDomain("bad host")).isFalse();
        Assertions.assertThat(RequestUtil.getBareHost("sub.example.co.uk")).isEqualTo("example.co.uk");
        Assertions.assertThat(RequestUtil.getBareHost("co.uk")).isEqualTo("co.uk");
        Assertions.assertThat(RequestUtil.getBareHost("8.8.8.8")).isEqualTo("8.8.8.8");
        Assertions.assertThat(RequestUtil.getBareHost("bad host")).isEqualTo("bad host");
    }

    @Test
    void retainedQuerySelectsOrderedParametersAndDropsEverythingElse() {
        Assertions.assertThat(RequestUtil.retainedQuery("drive.google.com", "/uc",
                "id=first&junk=x&export=download&id=second&&bare")).isEqualTo("?export=download&id=first");
        Assertions.assertThat(RequestUtil.retainedQuery("drive.google.com", "/other", "id=first")).isEmpty();
        Assertions.assertThat(RequestUtil.retainedQuery("google.com", "/share.google", "q")).isEqualTo("?q");
        Assertions.assertThat(RequestUtil.retainedQuery("google.com", "/share.google", "junk=x")).isEmpty();
        Assertions.assertThat(RequestUtil.retainedQuery("other.example", "/uc", "id=first")).isEmpty();
        Assertions.assertThat(RequestUtil.retainedQuery("drive.google.com", "/uc", "")).isEmpty();
        Assertions.assertThat(RequestUtil.retainedQuery("drive.google.com", "/uc", null)).isEmpty();
    }

    @Test
    void reconstructUriNormalizesPathsQueriesPortsAndIpv6Authorities() throws Exception {
        Provider provider = unlimitedProvider();

        URI input = new URI("http://drive.google.com/uc/?id=one&junk=x&export=download");
        Assertions.assertThat(RequestUtil.reconstructURI(input, "drive.google.com", "https",
                        provider, PROVIDER_NAME, HASHED_IP).toString())
                .isEqualTo("https://drive.google.com/uc?export=download&id=one");
        Assertions.assertThat(RequestUtil.reconstructURI(new URI("http://[2001:db8::1]:8443/path"),
                        "2001:db8::1", "https", provider, PROVIDER_NAME, HASHED_IP).toString())
                .isEqualTo("https://[2001:db8::1]:8443/path");
        Assertions.assertThat(RequestUtil.reconstructURI(new URI("urn:opaque"), "example.com", "https",
                provider, PROVIDER_NAME, HASHED_IP).toString()).isEqualTo("https://example.com");

        assertStatus(400, () -> RequestUtil.reconstructURI(new URI("http://example.com:0"), "example.com", "https",
                provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(400, () -> RequestUtil.reconstructURI(new URI("http://example.com:65536"), "example.com", "https",
                provider, PROVIDER_NAME, HASHED_IP));
        assertStatus(502, () -> RequestUtil.reconstructURI(new URI("http://example.com"), "bad host", "https",
                provider, PROVIDER_NAME, HASHED_IP));
    }

    @Test
    void validateUriRejectsSchemelessInputThatCannotBeRepairedWithHttps() {
        Provider provider = unlimitedProvider();

        for (String input : new String[]{".", "./", "a/..", "./."}) {
            Assertions.assertThatThrownBy(() -> RequestUtil.validateURI(input, provider, PROVIDER_NAME, HASHED_IP))
                    .as("input '%s'", input)
                    .isInstanceOf(StatusCodeException.class)
                    .hasMessage("400");
        }
    }

    @Test
    void validateUriStillRepairsSchemelessHostsThatParse() {
        Provider provider = unlimitedProvider();
        Assertions.assertThat(RequestUtil.validateURI("example.com/path", provider, PROVIDER_NAME, HASHED_IP))
                .hasToString("https://example.com/path");
    }

    @Test
    void validateHostRejectsEveryInvalidHostShapeWithA400() throws Exception {
        Provider provider = unlimitedProvider();

        assertRejected(new URI("http:/no-authority"), provider);
        assertRejected(new URI("http://:8080"), provider);
        assertRejected(new URI("http://" + "a".repeat(250) + ".example"), provider);
        assertRejected(new URI("http://bad::address"), provider);
        assertRejected(new URI("http://localhost"), provider);
        assertRejected(new URI("http://service.local"), provider);
        assertRejected(new URI("http://" + "a".repeat(64) + ".example"), provider);
    }

    @Test
    void validateHostKeepsAcceptingValidHostsAfterRejectionHandling() throws Exception {
        Provider provider = unlimitedProvider();
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://EXAMPLE.com."), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("example.com");
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://[2001:db8::1]:8443"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("2001:db8::1");
        Assertions.assertThat(RequestUtil.validateHost(new URI("http://8.8.8.8"), provider,
                PROVIDER_NAME, HASHED_IP)).isEqualTo("8.8.8.8");
    }

    @Test
    void invokesLegacyIpValidationOverload() throws Exception {
        Method validateIp = RequestUtil.class.getDeclaredMethod("validateIP",
                jakarta.servlet.http.HttpServletRequest.class, Provider.class, String.class);
        validateIp.setAccessible(true);
        var request = Mockito.mock(jakarta.servlet.http.HttpServletRequest.class);
        Mockito.when(request.getRemoteAddr()).thenReturn("8.8.8.8");
        Provider provider = unlimitedProvider();
        Assertions.assertThat(validateIp.invoke(null, request, provider, "test")).isNotNull();
    }

    private static void assertRejected(URI uri, Provider provider) {
        Assertions.assertThatThrownBy(() -> RequestUtil.validateHost(uri, provider, PROVIDER_NAME, HASHED_IP))
                .as("uri '%s'", uri)
                .isInstanceOf(StatusCodeException.class)
                .hasMessage("400");
    }

    private static Provider unlimitedProvider() {
        Provider provider = Mockito.mock(Provider.class);
        Mockito.when(provider.isRateLimitingEnabled()).thenReturn(false);
        Mockito.when(provider.isAbuseLimitingEnabled()).thenReturn(false);
        Mockito.when(provider.isInvalidRequestBlocked(ArgumentMatchers.anyString())).thenReturn(false);
        return provider;
    }

    private static void assertStatus(int status, org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        Assertions.assertThatThrownBy(action)
                .isInstanceOf(StatusCodeException.class)
                .hasMessage(String.valueOf(status));
    }
}
