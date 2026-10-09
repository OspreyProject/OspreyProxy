/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util.list;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

class LocalListHostTest {

    @Test
    void registryStyleHostsAreReadInsteadOfTreatedAsHostless() {
        Assertions.assertEquals("login_paypal.evil.com", LocalListUtil.hostOf(URI.create("https://login_paypal.evil.com/x")));
        Assertions.assertEquals("a_b.evil.com", LocalListUtil.hostOf(URI.create("https://user@a_b.evil.com:8443/x")));
        Assertions.assertEquals("example.com", LocalListUtil.hostOf(URI.create("https://example.com/")));
        Assertions.assertNull(LocalListUtil.hostOf(URI.create("mailto:someone@example.com")));
        Assertions.assertNull(LocalListUtil.hostOf(URI.create("https://a%20b.example/")));
    }
}
