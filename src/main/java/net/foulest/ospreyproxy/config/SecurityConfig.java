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
package net.foulest.ospreyproxy.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.ErrorUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Global security configuration for the proxy server.
 */
@Slf4j
@Configuration
public class SecurityConfig implements WebMvcConfigurer {

    // Maximum allowed body size (10 KB). Mirrors server.tomcat.max-http-form-post-size
    private static final int MAX_BODY_SIZE = 10_240;

    // HTTP methods that carry no request body; exempt from Content-Type enforcement
    private static final Set<String> BODYLESS_METHODS = Set.of(
            HttpMethod.GET.name(),
            HttpMethod.HEAD.name(),
            HttpMethod.OPTIONS.name(),
            HttpMethod.DELETE.name()
    );

    /**
     * Registers the security filter at order 1 (highest priority).
     * All requests pass through this filter before reaching any controller.
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

    /**
     * The security filter implementation.
     * Stateless and thread-safe: no instance fields, safe to share across virtual threads.
     */
    public static final class SecurityFilter implements Filter {

        @Override
        public void doFilter(@NonNull ServletRequest servletRequest,
                             @NonNull ServletResponse servletResponse,
                             @NonNull FilterChain chain) throws IOException, ServletException {
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            HttpServletResponse response = (HttpServletResponse) servletResponse;

            // Security headers on every response
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("Content-Security-Policy", "default-src 'none'");
            response.setHeader("Referrer-Policy", "no-referrer");
            response.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            String method = request.getMethod();

            // Skip Content-Type and size checks for bodyless methods
            if (BODYLESS_METHODS.contains(method)) {
                chain.doFilter(request, response);
                return;
            }

            long contentLength = request.getContentLengthLong();

            // Early rejection for requests declaring an oversized Content-Length.
            // getContentLengthLong() returns -1 when the header is absent (chunked
            // transfer), in which case the Tomcat connector limit handles it instead.
            if (contentLength > MAX_BODY_SIZE) {
                log.warn("Rejected request with oversized Content-Length: {} bytes", contentLength);
                sendError(response, HttpServletResponse.SC_BAD_REQUEST, ErrorUtil.BODY_400);
                return;
            }

            String rawContentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
            int length = MediaType.APPLICATION_JSON_VALUE.length();

            // Validate Content-Type: must be application/json (with optional charset param)
            boolean valid = rawContentType != null
                    && (rawContentType.equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)
                    || (rawContentType.regionMatches(true, 0, MediaType.APPLICATION_JSON_VALUE,
                    0, length)
                    && rawContentType.length() > length
                    && rawContentType.charAt(length) == ';'));

            // Sends error if the request is not valid
            if (!valid) {
                sendError(response, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, ErrorUtil.BODY_415);
                return;
            }

            chain.doFilter(request, response);
        }

        /**
         * Writes a JSON error body directly to the response without going through
         * Spring MVC's message converter pipeline. Safe to call before the chain
         * has been entered (i.e., before any controller or MVC processing).
         *
         * @param response The HttpServletResponse to write to.
         * @param status The HTTP status code to set on the response.
         * @param body The pre-serialized JSON error body string to write.
         */
        private static void sendError(@NonNull HttpServletResponse response,
                                      int status,
                                      @NonNull String body) throws IOException {
            response.setStatus(status);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());

            PrintWriter writer = response.getWriter();
            writer.write(body);
            writer.flush();
        }

        @Override
        public void init(FilterConfig filterConfig) {
            // No initialization needed
        }

        @Override
        public void destroy() {
            // No cleanup needed
        }
    }
}
