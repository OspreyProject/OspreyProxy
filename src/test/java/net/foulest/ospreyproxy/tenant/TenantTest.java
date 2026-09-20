/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.tenant;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class TenantTest {

    @Test
    void acceptsRequestsUntilEitherAggregateBudgetIsExhausted() {
        Tenant burstLimited = new Tenant("burst", new RateSettings(1, 60, 2, 60));
        Tenant sustainedLimited = new Tenant("sustained", new RateSettings(2, 60, 1, 60));

        Assertions.assertThat(burstLimited.id()).isEqualTo("burst");
        Assertions.assertThat(burstLimited.tryConsume()).isTrue();
        Assertions.assertThat(burstLimited.tryConsume()).isFalse();
        Assertions.assertThat(sustainedLimited.tryConsume()).isTrue();
        Assertions.assertThat(sustainedLimited.tryConsume()).isFalse();
    }
}
