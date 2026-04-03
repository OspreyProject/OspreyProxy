package net.foulest.ospreyproxy.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.ErrorUtil;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * A servlet filter that applies security headers to all responses and enforces
 * strict Content-Type and body size checks on incoming requests before they reach any controller.
 */
@Slf4j
public class SecurityFilter implements Filter {

    // Maximum allowed body size (10 KB)
    private static final int MAX_BODY_SIZE = 10_240;

    // HTTP methods that are allowed to be processed
    private static final Set<String> ALLOWED_METHODS = Set.of(
            HttpMethod.GET.name(),
            HttpMethod.POST.name(),
            HttpMethod.OPTIONS.name(),
            HttpMethod.HEAD.name()
    );

    // HTTP methods that carry no request body; exempt from Content-Type enforcement
    private static final Set<String> BODYLESS_METHODS = Set.of(
            HttpMethod.GET.name(),
            HttpMethod.HEAD.name(),
            HttpMethod.OPTIONS.name(),
            HttpMethod.DELETE.name()
    );

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
        response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setHeader("Cache-Control", "no-store");

        String method = request.getMethod();

        // Reject requests with disallowed HTTP methods before any further processing
        if (!ALLOWED_METHODS.contains(method)) {
            sendError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, ErrorUtil.BODY_405);
            return;
        }

        // Skip Content-Type and size checks for bodyless methods
        if (BODYLESS_METHODS.contains(method)) {
            chain.doFilter(request, response);
            return;
        }

        long contentLength = request.getContentLengthLong();

        // Reject requests with no declared Content-Length (e.g. chunked transfer encoding)
        // to prevent body size enforcement bypass
        if (contentLength < 0) {
            log.warn("Rejected request with missing Content-Length");
            sendError(response, HttpServletResponse.SC_BAD_REQUEST, ErrorUtil.BODY_400);
            return;
        }

        // Early rejection for requests declaring an oversized Content-Length
        if (contentLength > MAX_BODY_SIZE) {
            log.warn("Rejected request with oversized Content-Length: {} bytes", contentLength);
            sendError(response, HttpServletResponse.SC_BAD_REQUEST, ErrorUtil.BODY_400);
            return;
        }

        String rawContentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
        int length = MediaType.APPLICATION_JSON_VALUE.length();

        // Validate Content-Type: must be application/json (with optional charset param)
        boolean valid = rawContentType != null
                && (MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(rawContentType)
                || (rawContentType.regionMatches(true, 0, MediaType.APPLICATION_JSON_VALUE, 0, length)
                && rawContentType.length() > length
                && rawContentType.charAt(length) == ';'));

        // Sends error if the request is not valid
        if (!valid) {
            log.warn("Rejected request with invalid Content-Type: {}", rawContentType);
            sendError(response, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, ErrorUtil.BODY_415);
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * Writes an error response with the given status and pre-serialized JSON body.
     *
     * @param response The HttpServletResponse to write to.
     * @param status The HTTP status code to set on the response.
     * @param body The pre-serialized JSON error body string to write.
     */
    @SuppressWarnings("NestedMethodCall")
    private static void sendError(@NonNull HttpServletResponse response, int status,
                                  @NonNull String body) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // Writes the body
        PrintWriter writer = response.getWriter();
        writer.write(body);
        writer.flush();
    }
}
