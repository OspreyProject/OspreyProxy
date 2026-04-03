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
package net.foulest.ospreyproxy.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Global security configuration for the proxy server.
 */
@Configuration
public class SecurityConfig implements WebMvcConfigurer {

    /**
     * Registers the security filter at order 1 (highest priority).
     * All requests pass through this filter before reaching any controller.
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
