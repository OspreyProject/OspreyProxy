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
package net.foulest.ospreyproxy.providers.other;

import jakarta.annotation.PostConstruct;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import org.apache.hc.core5.http.Method;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

/**
 * Provider implementation for PhishingBox.
 */
@Component
public class PhishingBox extends AbstractProvider {

    private static final String API_KEY = System.getenv("PHISHINGBOX_API_KEY");

    @PostConstruct
    public void validateConfig() {
        if (isEnabled() && (API_KEY == null || API_KEY.isBlank()
                || !UUID_PATTERN.matcher(API_KEY).matches())) {
            throw new IllegalStateException("PHISHINGBOX_API_KEY environment variable is invalid or not set");
        }
    }

    @Override
    public @NonNull String getDisplayName() {
        return "PhishingBox";
    }

    @Override
    public @NonNull String getShortName() {
        return "phishingBox";
    }

    @Override
    public @NonNull String getEndpointName() {
        return "phishingbox";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public @NonNull String getApiKey() {
        return API_KEY != null ? API_KEY : "";
    }

    @Override
    public @NonNull Method getMethod() {
        return Method.POST;
    }

    @Override
    public boolean isRateLimitingEnabled() {
        return false;
    }
}
