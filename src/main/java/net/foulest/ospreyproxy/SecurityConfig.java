package net.foulest.ospreyproxy;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;

@Configuration
public class SecurityConfig {

    @Bean
    public FilterRegistrationBean<Filter> securityHeaders() {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();

        bean.setFilter((req, res, chain) -> {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;
            String contentType = request.getContentType();
            MediaType parsed;

            // Sets the default content type to application/json for all responses
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            // Rejects requests with no content type or blank content type
            if (contentType == null || contentType.isBlank()) {
                response.setStatus(415);
                response.getWriter().write("{\"error\": \"Content-Type must be application/json\"}");
                return;
            }

            // Parses the content type and returns a 415 error if it's invalid
            try {
                parsed = MediaType.parseMediaType(contentType);
            } catch (RuntimeException e) {
                response.setStatus(415);
                response.getWriter().write("{\"error\": \"Content-Type must be application/json\"}");
                return;
            }

            // Only allows application/json content types for all requests
            if (!parsed.equalsTypeAndSubtype(MediaType.APPLICATION_JSON)) {
                response.setStatus(415);
                response.getWriter().write("{\"error\": \"Content-Type must be application/json\"}");
                return;
            }

            // Prevents MIME-type sniffing
            response.setHeader("X-Content-Type-Options", "nosniff");

            // Prevents framing (clickjacking)
            response.setHeader("X-Frame-Options", "DENY");

            // Strict CSP (we don't have any assets)
            response.setHeader("Content-Security-Policy", "default-src 'none'");

            // Don't send referrer information to any site
            response.setHeader("Referrer-Policy", "no-referrer");

            // Blocks XSS in older browsers
            response.setHeader("X-XSS-Protection", "1; mode=block");

            // Disables access to sensitive browser APIs
            response.setHeader("Permissions-Policy",
                    "geolocation=(), camera=(), microphone=(), payment=()");

            // Enforces HTTPS for all subdomains
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            // Tries to prevent responses from being cached by proxies or clients
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");

            chain.doFilter(req, res);
        });

        bean.addUrlPatterns("/*");
        return bean;
    }
}
