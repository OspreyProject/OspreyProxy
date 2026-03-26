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
import net.foulest.ospreyproxy.util.dns.DNSUtil;
import net.foulest.ospreyproxy.util.dns.DNSFormat;
import net.foulest.ospreyproxy.util.dns.Record;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Provider implementation for Control D Security DNS.
 */
@Component
public class ControlDSecurity extends AbstractDNSProvider {

    private static final String API_URL = "https://freedns.controld.com/no-malware-typo?name=";
    private static final String BLOCK_IP = "0.0.0.0";

    @Override
    public @NonNull String getDisplayName() {
        return "Control D Security";
    }

    @Override
    public @NonNull String getShortName() {
        return "controlDSecurity";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "controld-security";
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
    protected DNSFormat getDnsFormat() {
        return DNSFormat.NAME_MESSAGE;
    }

    @Override
    protected LookupResult interpret(byte @Nullable [] rawBytes,
                                     @Nullable Map<String, Object> jsonResponse,
                                     @NonNull String host) {
        if (rawBytes == null || rawBytes.length == 0) {
            return LookupResult.FAILED;
        }

        boolean blocked = DNSUtil.walkAnswers(rawBytes, (type, rdata) -> {
            if (type == Record.A) {
                String ip = DNSUtil.parseIPv4(rdata);
                return BLOCK_IP.equals(ip);
            }
            return false;
        });
        return blocked ? LookupResult.MALICIOUS : LookupResult.ALLOWED;
    }
}
