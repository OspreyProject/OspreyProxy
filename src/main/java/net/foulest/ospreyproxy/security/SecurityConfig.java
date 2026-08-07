/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
package net.foulest.ospreyproxy.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * Global security configuration for the proxy server.
 */
@Configuration
public class SecurityConfig {

    /**
     * The single web origin allowed to call the browser-facing /check endpoint cross-origin.
     * Every other endpoint stays same-origin only, since the extension calls them with host
     * permissions and needs no CORS.
     */
    @Value("${osprey.check.allowed-origin:https://osprey.ac}")
    private String checkAllowedOrigin;

    /**
     * Registers a servlet-level {@link CorsFilter} at order 0 so preflight OPTIONS requests
     * to /check are intercepted and answered immediately before reaching the {@link SecurityFilter}.
     *
     * @return A FilterRegistrationBean registering the CorsFilter for /check.
     */
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(checkAllowedOrigin));
        config.setAllowedHeaders(List.of("Content-Type", "Accept"));
        config.setAllowedMethods(List.of("POST", "OPTIONS"));
        config.setMaxAge(600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/check", config);

        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(new CorsFilter(source));
        registration.setOrder(0);
        registration.setName("corsFilter");
        return registration;
    }

    /**
     * Registers the security filter at order 1.
     * All requests pass through this filter after CORS handling has completed.
     *
     * @return A FilterRegistrationBean that registers the SecurityFilter for all URL patterns.
     */
    @Bean
    public FilterRegistrationBean<SecurityFilter> securityFilterRegistration() {
        FilterRegistrationBean<SecurityFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SecurityFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        registration.setName("securityFilter");
        return registration;
    }
}
