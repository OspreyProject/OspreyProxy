/*
 * OspreyProxy - backend code for our proxy server using Spring MVC.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package net.foulest.ospreyproxy.providers.dns;

import net.foulest.ospreyproxy.providers.AbstractDNSProvider;
import net.foulest.ospreyproxy.result.LookupResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Provider implementation for Quad9 DNS.
 */
@Component
public class Quad9 extends AbstractDNSProvider {

    private static final String API_URL = "https://dns.quad9.net/dns-query?dns=";
    private static final int NXDOMAIN_RCODE = 3; // RCODE 3 (NXDOMAIN) in the flags byte

    @Override
    public @NonNull String getDisplayName() {
        return "Quad9";
    }

    @Override
    public @NonNull String getShortName() {
        return "quad9";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "quad9";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    protected LookupResult interpret(byte @Nullable [] rawBytes,
                                     @Nullable Map<String, Object> jsonResponse,
                                     @NonNull String host) {
        if (rawBytes == null || rawBytes.length == 0) {
            return LookupResult.FAILED;
        }

        boolean blocked = rawBytes.length >= 4 && (rawBytes[3] & 0xFF) == NXDOMAIN_RCODE;
        return blocked ? LookupResult.MALICIOUS : LookupResult.ALLOWED;
    }
}
