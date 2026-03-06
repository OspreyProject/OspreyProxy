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

            // Set default content type to application/json for all responses
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            // Reject requests with no content type or blank content type
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

            // Only allow application/json content type for all requests
            if (!parsed.equalsTypeAndSubtype(MediaType.APPLICATION_JSON)) {
                response.setStatus(415);
                response.getWriter().write("{\"error\": \"Content-Type must be application/json\"}");
                return;
            }

            // Prevent MIME-type sniffing
            response.setHeader("X-Content-Type-Options", "nosniff");

            // Prevent framing (clickjacking)
            response.setHeader("X-Frame-Options", "DENY");

            // Strict CSP — this API serves no assets
            response.setHeader("Content-Security-Policy", "default-src 'none'");

            // Never send Referer headers upstream
            response.setHeader("Referrer-Policy", "no-referrer");

            // Block XSS in older browsers
            response.setHeader("X-XSS-Protection", "1; mode=block");

            // Disable access to sensitive browser APIs
            response.setHeader("Permissions-Policy",
                    "geolocation=(), camera=(), microphone=(), payment=()");

            // Enforce HTTPS, including subdomains
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            // Prevent responses from being cached by proxies or clients
            response.setHeader("Cache-Control", "no-store");
            response.setHeader("Pragma", "no-cache");

            chain.doFilter(req, res);
        });

        bean.addUrlPatterns("/*");
        return bean;
    }
}
