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

import jakarta.annotation.PostConstruct;
import net.foulest.ospreyproxy.tenant.TenantService;
import net.foulest.ospreyproxy.util.RequestUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * Global security configuration for the proxy server.
 */
@Configuration
public class SecurityConfig {

    /**
     * The single web origin allowed to call the browser-facing /check endpoint cross-origin.
     * Every other endpoint stays same-origin only, except the provider endpoints, which allow the
     * extension's own origins.
     */
    @Value("${osprey.check.allowed-origin:https://osprey.ac}")
    private String checkAllowedOrigin;

    /**
     * Origin patterns of the browser extension, which calls the provider endpoints directly and so
     * needs CORS against any proxy it has no host permission for (every self-hosted deployment).
     */
    @Value("${osprey.provider.allowed-origin-patterns:chrome-extension://*,moz-extension://*,safari-web-extension://*}")
    private List<String> extensionOriginPatterns = List.of(
            "chrome-extension://*", "moz-extension://*", "safari-web-extension://*");

    /**
     * Header carrying the tenant key, which must be allowed in provider preflights.
     */
    @Value("${osprey.tenant.auth.header:X-Osprey-Tenant-Key}")
    private String tenantHeader = "X-Osprey-Tenant-Key";

    /**
     * Peer addresses whose X-Real-IP header is trusted. Defaults to loopback (Nginx on the same host).
     * Add the proxy's address when it runs elsewhere; leave the CDN out and configure Nginx's real_ip
     * module so the header already carries the true client address.
     */
    @Value("${osprey.proxy.trusted-addresses:127.0.0.1,::1}")
    private List<String> trustedProxyAddresses = List.of("127.0.0.1", "::1");

    /**
     * Applies the trusted proxy list used when resolving client IPs.
     */
    @PostConstruct
    public void configureTrustedProxies() {
        List<String> addresses = new ArrayList<>(trustedProxyAddresses);

        // "::1" has several textual forms; trust them all together
        if (addresses.contains("::1")) {
            addresses.add("0:0:0:0:0:0:0:1");
        }
        RequestUtil.setTrustedProxies(addresses);
    }

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

        // The read-only result lookup is a browser GET from the same single origin. The internal
        // index feed is deliberately not registered here, so it stays same-origin only.
        CorsConfiguration resultConfig = new CorsConfiguration();
        resultConfig.setAllowedOrigins(List.of(checkAllowedOrigin));
        resultConfig.setAllowedHeaders(List.of("Content-Type", "Accept"));
        resultConfig.setAllowedMethods(List.of("GET", "OPTIONS"));
        resultConfig.setMaxAge(600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/check", config);
        source.registerCorsConfiguration("/result", resultConfig);

        // The website contact form posts submissions and verification tokens from the same origin.
        CorsConfiguration contactConfig = new CorsConfiguration();
        contactConfig.setAllowedOrigins(List.of(checkAllowedOrigin));
        contactConfig.setAllowedHeaders(List.of("Content-Type", "Accept"));
        contactConfig.setAllowedMethods(List.of("POST", "OPTIONS"));
        contactConfig.setMaxAge(600L);
        source.registerCorsConfiguration("/contact/**", contactConfig);

        // The extension calls provider endpoints directly. Against a self-hosted proxy it has no host
        // permission, so the browser sends a preflight carrying the tenant key header. Extension
        // origins are allowed here; access is still gated by the tenant key. Registered last so the
        // specific paths above win.
        List<String> headers = new ArrayList<>(List.of("Content-Type", "Accept"));
        headers.add(tenantHeader);

        CorsConfiguration providerConfig = new CorsConfiguration();
        providerConfig.setAllowedOriginPatterns(extensionOriginPatterns);
        providerConfig.setAllowedHeaders(headers);
        providerConfig.setAllowedMethods(List.of("POST", "OPTIONS"));
        providerConfig.setMaxAge(600L);
        source.registerCorsConfiguration("/*", providerConfig);

        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(new CorsFilter(source));
        registration.setOrder(0);
        registration.setName("corsFilter");
        return registration;
    }

    /**
     * Registers the security filter at order 1.
     * All requests pass through this filter after CORS handling has completed. The filter also enforces
     * per-tenant authentication on the extension-facing provider endpoints when it is enabled.
     *
     * @param tenantService The tenant registry the filter authenticates and meters requests against.
     * @return A FilterRegistrationBean that registers the SecurityFilter for all URL patterns.
     */
    @Bean
    public FilterRegistrationBean<SecurityFilter> securityFilterRegistration(TenantService tenantService) {
        FilterRegistrationBean<SecurityFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SecurityFilter(tenantService));
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        registration.setName("securityFilter");
        return registration;
    }
}
