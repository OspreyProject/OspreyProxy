package net.foulest.ospreyproxy.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.util.ErrorUtil;
import org.jetbrains.annotations.Contract;
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
    public void doFilter(@NonNull ServletRequest request,
                         @NonNull ServletResponse response,
                         @NonNull FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = getServletResponse((HttpServletResponse) response);
        String method = httpRequest.getMethod();

        // Reject requests with disallowed HTTP methods before any further processing
        if (!ALLOWED_METHODS.contains(method)) {
            sendError(httpResponse, HttpServletResponse.SC_METHOD_NOT_ALLOWED, ErrorUtil.BODY_405);
            return;
        }

        // Skip Content-Type and size checks for bodyless methods
        if (BODYLESS_METHODS.contains(method)) {
            chain.doFilter(httpRequest, httpResponse);
            return;
        }

        long contentLength = httpRequest.getContentLengthLong();

        // Reject requests with no declared Content-Length (e.g. chunked transfer encoding)
        // to prevent body size enforcement bypass
        if (contentLength < 0) {
            log.warn("Rejected request with missing Content-Length");
            sendError(httpResponse, HttpServletResponse.SC_BAD_REQUEST, ErrorUtil.BODY_400);
            return;
        }

        // Early rejection for requests declaring an oversized Content-Length
        if (contentLength > MAX_BODY_SIZE) {
            log.warn("Rejected request with oversized Content-Length: {} bytes", contentLength);
            sendError(httpResponse, HttpServletResponse.SC_BAD_REQUEST, ErrorUtil.BODY_400);
            return;
        }

        String rawContentType = httpRequest.getHeader(HttpHeaders.CONTENT_TYPE);
        int length = MediaType.APPLICATION_JSON_VALUE.length();

        // Sends error if the Content-Type is not valid
        if (!isContentTypeValid(rawContentType, length)) {
            log.warn("Rejected request with invalid Content-Type");
            sendError(httpResponse, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, ErrorUtil.BODY_415);
            return;
        }

        chain.doFilter(httpRequest, httpResponse);
    }

    /**
     * Applies security headers to the response and returns it for further processing.
     *
     * @param response The HttpServletResponse to apply headers to.
     * @return The same HttpServletResponse instance with security headers applied, ready for further processing.
     */
    @Contract("_ -> param1")
    private static @NonNull HttpServletResponse getServletResponse(@NonNull HttpServletResponse response) {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setHeader("Cache-Control", "no-store");
        return response;
    }

    /**
     * Validates the Content-Type header against "application/json" with optional parameters.
     *
     * @param rawContentType The raw Content-Type header value from the request.
     * @param length The length of the "application/json" string constant, precomputed for efficiency.
     * @return {@code true} if the Content-Type is valid, {@code false} otherwise.
     */
    @Contract("null, _ -> false")
    private static boolean isContentTypeValid(String rawContentType, int length) {
        // Checks if the content type is null
        if (rawContentType == null) {
            return false;
        }

        // Checks if the content type is exactly "application/json" (case-insensitive)
        if (!MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(rawContentType)) {
            return false;
        }

        // Checks if the content type starts with "application/json" (case-insensitive) and is followed by a ';' for parameters
        if (!rawContentType.regionMatches(true, 0, MediaType.APPLICATION_JSON_VALUE, 0, length)) {
            return false;
        }

        // If there are additional characters after "application/json",
        // the next character must be ';' to allow for parameters like charset
        if (rawContentType.length() > length) {
            return rawContentType.charAt(length) == ';';
        }
        return true;
    }

    /**
     * Writes an error response with the given status and pre-serialized JSON body.
     *
     * @param response The HttpServletResponse to write to.
     * @param status The HTTP status code to set on the response.
     * @param body The pre-serialized JSON error body string to write.
     */
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
