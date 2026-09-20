/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

class NetworkUtilTest {

    @Test
    void dnsResolverAcceptsPublicNumericAddressAndRejectsPrivateOne() throws Exception {
        Assertions.assertThat(NetworkUtil.DNS_RESOLVER.resolveCanonicalHostname("Example.COM")).isEqualTo("Example.COM");
        InetAddress[] resolved = NetworkUtil.DNS_RESOLVER.resolve("8.8.8.8");
        Assertions.assertThat(resolved).hasSize(1);
        Assertions.assertThat(resolved[0].getHostAddress()).isEqualTo("8.8.8.8");
        Assertions.assertThatThrownBy(() -> NetworkUtil.DNS_RESOLVER.resolve("127.0.0.1"))
                .isInstanceOf(UnknownHostException.class)
                .hasMessageContaining("Blocked");
    }

    @Test
    void dnsResolverRejectsAnEmptyResolutionResult() {
        try (MockedStatic<InetAddress> addresses = Mockito.mockStatic(InetAddress.class)) {
            addresses.when(() -> InetAddress.getAllByName("empty-resolution.test"))
                    .thenReturn(new InetAddress[0]);

            Assertions.assertThatThrownBy(() -> NetworkUtil.DNS_RESOLVER.resolve("empty-resolution.test"))
                    .isInstanceOf(UnknownHostException.class)
                    .hasMessage("No safe addresses resolved for: empty-resolution.test");
        }
    }

    @Test
    void privateAddressBlocksStandardAndSpecialIpv4Ranges() throws Exception {
        Assertions.assertThat(isPrivate("127.0.0.1")).isTrue();
        Assertions.assertThat(isPrivate("10.0.0.1")).isTrue();
        Assertions.assertThat(isPrivate("169.254.1.1")).isTrue();
        Assertions.assertThat(isPrivate("0.0.0.0")).isTrue();
        Assertions.assertThat(isPrivate("224.0.0.1")).isTrue();
        Assertions.assertThat(isPrivate("0.1.2.3")).isTrue();
        Assertions.assertThat(isPrivate("255.255.255.255")).isTrue();
        Assertions.assertThat(isPrivate("255.255.255.0")).isTrue();
        Assertions.assertThat(isPrivate("255.255.0.0")).isTrue();
        Assertions.assertThat(isPrivate("255.0.0.0")).isTrue();
        Assertions.assertThat(isPrivate("100.64.0.1")).isTrue();
        Assertions.assertThat(isPrivate("100.127.255.255")).isTrue();
        Assertions.assertThat(isPrivate("100.63.255.255")).isFalse();
        Assertions.assertThat(isPrivate("100.128.0.1")).isFalse();
        Assertions.assertThat(isPrivate("192.0.0.1")).isTrue();
        Assertions.assertThat(isPrivate("192.0.2.1")).isTrue();
        Assertions.assertThat(isPrivate("192.0.3.1")).isFalse();
        Assertions.assertThat(isPrivate("192.0.1.1")).isFalse();
        Assertions.assertThat(isPrivate("192.1.2.3")).isFalse();
        Assertions.assertThat(isPrivate("198.18.0.1")).isTrue();
        Assertions.assertThat(isPrivate("198.19.255.255")).isTrue();
        Assertions.assertThat(isPrivate("198.17.255.255")).isFalse();
        Assertions.assertThat(isPrivate("198.20.0.1")).isFalse();
        Assertions.assertThat(isPrivate("198.51.100.1")).isTrue();
        Assertions.assertThat(isPrivate("198.51.99.1")).isFalse();
        Assertions.assertThat(isPrivate("203.0.113.1")).isTrue();
        Assertions.assertThat(isPrivate("203.0.112.1")).isFalse();
        Assertions.assertThat(isPrivate("203.1.113.1")).isFalse();
        Assertions.assertThat(isPrivate("240.0.0.1")).isTrue();
        Assertions.assertThat(isPrivate("8.8.8.8")).isFalse();
        Assertions.assertThat(isPrivate(Mockito.mock(InetAddress.class))).isFalse();
    }

    @Test
    void privateAddressBlocksEmbeddedAndSpecialIpv6Ranges() throws Exception {
        Assertions.assertThat(isPrivate(ipv6(mapped(127, 0, 0, 1)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(mapped(8, 8, 8, 8)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0xfc)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(bytes(0xfd)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x01, 0, 0)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x00)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x01, 0x01, 0)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x01, 0, 0x01)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x02, 127, 0, 0, 1)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x02, 8, 8, 8, 8)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(compatible(127, 0, 0, 1)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(compatible(8, 8, 8, 8)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(nat64(1, 127, 0, 0, 1)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(nat64(0, 127, 0, 0, 1)))).isTrue();
        Assertions.assertThat(isPrivate(ipv6(nat64(0, 8, 8, 8, 8)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(nat64(2, 8, 8, 8, 8)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0, 0x63)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0, 0x64, 0xfe)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0, 0x64, 0xff, 0x9a)))).isFalse();
        Assertions.assertThat(isPrivate(ipv6(bytes(0x20, 0x01, 0x0d, 0xb8)))).isFalse();
    }

    @Test
    void hostnameChecksCoverNormalizationNamesAndNumericLiterals() {
        Assertions.assertThat(NetworkUtil.isPrivateHost("  LOCALHOST.  ")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("local")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("internal")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("service.local")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("service.internal")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("service.localhost")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("127.0.0.1")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("8.8.8.8")).isFalse();
        Assertions.assertThat(NetworkUtil.isPrivateHost("not-an-ip:")).isTrue();
        Assertions.assertThat(NetworkUtil.isPrivateHost("public.example")).isFalse();
    }

    @Test
    void literalRecognitionAndStrictParsersCoverAllInputShapes() {
        Assertions.assertThat(NetworkUtil.isIpLiteral("2001:db8::1")).isTrue();
        Assertions.assertThat(NetworkUtil.isIpLiteral("192.168.0.1")).isTrue();
        Assertions.assertThat(NetworkUtil.isIpLiteral("0x7f.0.0.1")).isFalse();
        Assertions.assertThat(NetworkUtil.isIpv6Literal("2001:db8::1")).isTrue();
        Assertions.assertThat(NetworkUtil.isIpv6Literal("2001:db8::1%zone")).isFalse();
        Assertions.assertThat(NetworkUtil.isIpv6Literal("[2001:db8::1]")).isFalse();
        Assertions.assertThat(NetworkUtil.isIpv6Literal("2001:db8::1]")).isFalse();
        Assertions.assertThat(NetworkUtil.isIpv6Literal("not-an-ip")).isFalse();
        Assertions.assertThat(NetworkUtil.isIpv6Literal("bad::address")).isFalse();

        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("192.168.0.1")).isTrue();
        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("1.2.3")).isFalse();
        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("1..3.4")).isFalse();
        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("0000.2.3.4")).isFalse();
        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("1.2.x.4")).isFalse();
        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("1.2./.4")).isFalse();
        Assertions.assertThat(NetworkUtil.isDottedDecimalIpv4("256.2.3.4")).isFalse();
    }

    @Test
    void uriEncodingAndDomainNormalizationCoverReplacementAndTrailingDotRules() {
        Assertions.assertThat(NetworkUtil.encodeIllegalUriChars("http://example.com/a b[%]|{}^`?ok=%20&bad=%"))
                .isEqualTo("http://example.com/a%20b%5B%25%5D%7C%7B%7D%5E%60?ok=%20&bad=%25");
        Assertions.assertThat(NetworkUtil.encodeIllegalUriChars("e\u0301")).isEqualTo("\u00e9");
        Assertions.assertThat(NetworkUtil.normalize(" Example.COM. ")).isEqualTo("example.com");
        Assertions.assertThat(NetworkUtil.normalize("   ")).isEmpty();
        Assertions.assertThat(NetworkUtil.normalize("example.com..")).isEqualTo("example.com.");
    }

    @Test
    void treatsUnconstructableEmbeddedIpv4AddressesAsPrivate() throws Exception {
        Method privateAddress = NetworkUtil.class.getDeclaredMethod("isPrivateAddress", InetAddress.class);
        privateAddress.setAccessible(true);
        try (MockedStatic<InetAddress> addresses = Mockito.mockStatic(InetAddress.class, Mockito.CALLS_REAL_METHODS)) {
            addresses.when(() -> InetAddress.getByAddress(ArgumentMatchers.any(byte[].class)))
                    .thenThrow(new UnknownHostException("broken"));
            Assertions.assertThat(privateAddress.invoke(null, ipv6(mapped(8, 8, 8, 8)))).isEqualTo(true);
            Assertions.assertThat(privateAddress.invoke(null, ipv6(sixToFour(8, 8, 8, 8)))).isEqualTo(true);
            Method embedded = NetworkUtil.class.getDeclaredMethod("isEmbeddedV4Private", byte[].class);
            embedded.setAccessible(true);
            Assertions.assertThat(embedded.invoke(null, new byte[4])).isEqualTo(true);
        }
    }

    private static boolean isPrivate(String address) throws Exception {
        return isPrivate(InetAddress.getByName(address));
    }

    private static boolean isPrivate(InetAddress address) throws Exception {
        Method method = NetworkUtil.class.getDeclaredMethod("isPrivateAddress", InetAddress.class);
        method.setAccessible(true);
        return (boolean) method.invoke(null, address);
    }

    private static Inet6Address ipv6(byte[] bytes) throws UnknownHostException {
        return Inet6Address.getByAddress(null, bytes, -1);
    }

    private static byte[] mapped(int a, int b, int c, int d) {
        byte[] bytes = new byte[16];
        bytes[10] = (byte) 0xff;
        bytes[11] = (byte) 0xff;
        bytes[12] = (byte) a;
        bytes[13] = (byte) b;
        bytes[14] = (byte) c;
        bytes[15] = (byte) d;
        return bytes;
    }

    private static byte[] compatible(int a, int b, int c, int d) {
        byte[] bytes = new byte[16];
        bytes[12] = (byte) a;
        bytes[13] = (byte) b;
        bytes[14] = (byte) c;
        bytes[15] = (byte) d;
        return bytes;
    }

    private static byte[] sixToFour(int a, int b, int c, int d) {
        byte[] bytes = new byte[16];
        bytes[0] = 0x20;
        bytes[1] = 0x02;
        bytes[2] = (byte) a;
        bytes[3] = (byte) b;
        bytes[4] = (byte) c;
        bytes[5] = (byte) d;
        return bytes;
    }

    private static byte[] nat64(int fifthByte, int a, int b, int c, int d) {
        byte[] bytes = bytes(0, 0x64, 0xff, 0x9b);
        bytes[4] = (byte) fifthByte;
        bytes[12] = (byte) a;
        bytes[13] = (byte) b;
        bytes[14] = (byte) c;
        bytes[15] = (byte) d;
        return bytes;
    }

    private static byte[] bytes(int... values) {
        byte[] bytes = new byte[16];
        for (int i = 0; i < values.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }
}
