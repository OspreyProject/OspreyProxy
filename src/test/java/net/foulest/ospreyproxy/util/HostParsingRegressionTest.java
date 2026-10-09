/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

class HostParsingRegressionTest {

    @Test
    void asciiHostsAcceptUnderscoresAndEdgeHyphensLikeBrowsers() {
        Assertions.assertEquals("a_b.example.com", NetworkUtil.toAsciiHost("A_B.example.com"));
        Assertions.assertEquals("-x.example.com", NetworkUtil.toAsciiHost("-x.example.com"));
        Assertions.assertEquals("x-.example.com", NetworkUtil.toAsciiHost("x-.example.com"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> NetworkUtil.toAsciiHost("a..example.com"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> NetworkUtil.toAsciiHost("a b.example.com"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> NetworkUtil.toAsciiHost("x".repeat(64) + ".com"));
    }

    @Test
    void trustedProxyAddressesMatchEveryTextualFormOfTheSameAddress() {
        Assertions.assertEquals("0:0:0:0:0:0:0:1", RequestUtil.canonicalIpLiteral("::1"));
        Assertions.assertEquals("fd00:0:0:0:0:0:0:1", RequestUtil.canonicalIpLiteral("FD00::1"));
        Assertions.assertEquals("fd00:0:0:0:0:0:0:1", RequestUtil.canonicalIpLiteral("[fd00:0:0:0:0:0:0:1]"));
        Assertions.assertEquals("10.0.0.5", RequestUtil.canonicalIpLiteral(" 10.0.0.5 "));
        Assertions.assertNull(RequestUtil.canonicalIpLiteral("proxy.internal"));
        Assertions.assertNull(RequestUtil.canonicalIpLiteral(null));

        try {
            RequestUtil.setTrustedProxies(List.of("fd00::1"));
            Assertions.assertTrue(RequestUtil.getTrustedProxies().contains("fd00:0:0:0:0:0:0:1"));
        } finally {
            RequestUtil.setTrustedProxies(List.of("127.0.0.1", "::1"));
        }
    }
}
