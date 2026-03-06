package net.foulest.ospreyproxy;

import jakarta.servlet.Filter;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

@Configuration
public class SecurityConfig {

    // Constant for error message thrown when the content type is invalid
    private static final String CONTENT_TYPE_ERROR = "{\"error\": \"Content-Type must be application/json\"}";

    // Maximum request body size in bytes (10 KB)
    private static final int MAX_BODY_SIZE = 10_240;

    // Error message for oversized request bodies
    private static final String BODY_TOO_LARGE_ERROR = "{\"error\": \"Request body too large\"}";

    /**
     * Filter that enforces a hard body-size limit for ALL content types,
     * including chunked Transfer-Encoding where Content-Length is absent.
     * Registered with the highest precedence so it runs before Spring reads the body.
     */
    @Bean
    public FilterRegistrationBean<Filter> bodySizeFilter() {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>();

        bean.setFilter((req, res, chain) -> {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;

            // Wrap the request with a byte-counting input stream
            chain.doFilter(new BodyLimitRequestWrapper(request, MAX_BODY_SIZE, response), res);
        });

        bean.addUrlPatterns("/*");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

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
                response.getWriter().write(CONTENT_TYPE_ERROR);
                return;
            }

            // Parses the content type and returns a 415 error if it's invalid
            try {
                parsed = MediaType.parseMediaType(contentType);
            } catch (RuntimeException e) {
                response.setStatus(415);
                response.getWriter().write(CONTENT_TYPE_ERROR);
                return;
            }

            // Only allows application/json content types for all requests
            if (!parsed.equalsTypeAndSubtype(MediaType.APPLICATION_JSON)) {
                response.setStatus(415);
                response.getWriter().write(CONTENT_TYPE_ERROR);
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

    /**
     * Request wrapper that enforces a byte-count limit on the input stream.
     * Aborts with 413 if the client sends more bytes than allowed, preventing
     * oversized bodies via chunked Transfer-Encoding from bypassing Content-Length checks.
     */
    private static class BodyLimitRequestWrapper extends HttpServletRequestWrapper {

        private final int maxBytes;
        private final HttpServletResponse response;

        BodyLimitRequestWrapper(HttpServletRequest request, int maxBytes, HttpServletResponse response) {
            super(request);
            this.maxBytes = maxBytes;
            this.response = response;
        }

        @Override
        public @NonNull ServletInputStream getInputStream() throws IOException {
            ServletInputStream original = super.getInputStream();
            return new LimitedServletInputStream(original, maxBytes, response);
        }

        @Override
        public @NonNull BufferedReader getReader() throws IOException {
            ServletInputStream inputStream = getInputStream();
            return new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        }
    }

    /**
     * ServletInputStream decorator that counts bytes read and sends a 413
     * error response when the limit is exceeded.
     */
    private static class LimitedServletInputStream extends ServletInputStream {

        private final ServletInputStream delegate;
        private final int maxBytes;
        private final HttpServletResponse response;
        private final AtomicInteger bytesRead = new AtomicInteger(0);

        LimitedServletInputStream(ServletInputStream delegate, int maxBytes, HttpServletResponse response) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
            this.response = response;
            bytesRead.set(0);
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();

            if (b != -1) {
                if (bytesRead.incrementAndGet() > maxBytes) {
                    sendError();
                    throw new IOException("Request body too large");
                }
            }
            return b;
        }

        @Override
        public int read(byte @NonNull [] b, int off, int len) throws IOException {
            int count = delegate.read(b, off, len);

            if (count > 0) {
                if (bytesRead.addAndGet(count) > maxBytes) {
                    sendError();
                    throw new IOException("Request body too large");
                }
            }
            return count;
        }

        private void sendError() throws IOException {
            if (!response.isCommitted()) {
                response.setStatus(413);
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                response.getWriter().write(BODY_TOO_LARGE_ERROR);
                response.getWriter().flush();
            }
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            delegate.setReadListener(readListener);
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
