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
package net.foulest.ospreyproxy.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.Provider;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.jspecify.annotations.NonNull;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;

import java.net.*;
import java.util.Locale;
import java.util.Map;

/**
 * Utility class for validating incoming requests to the proxy.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class RequestUtil {

    // Constants for validation limits
    private static final int MAX_IP_LITERAL_LENGTH = 45;
    private static final int MAX_HOST_LENGTH = 253;
    private static final int MAX_DNS_LABEL_LENGTH = 63;

    /**
     * Validates and rate-limits a request's IP address, and returns a hashed IP.
     *
     * @param request      The request to validate.
     * @param provider     The provider to lookup rate limits against.
     * @param providerName The name of the provider.
     * @return A hashed representation of the client's IP address for rate limiting purposes.
     * @throws StatusCodeException If the IP address is found to be invalid/blocked.
     */
    public static String validateIP(@NonNull HttpServletRequest request, Provider provider, String providerName) {
        String headerIp = request.getHeader("X-Real-IP");
        String realIp = normalizeClientIp(headerIp);

        // Checks if the X-Real-IP header is present but malformed
        if (headerIp != null && !headerIp.isBlank() && realIp == null) {
            log.warn("[{}] Ignoring malformed X-Real-IP header", providerName);
        }

        // Falls back to the remote address if X-Real-IP is missing or invalid
        if (realIp == null) {
            realIp = normalizeClientIp(request.getRemoteAddr());
        }

        // If the remote address is also invalid, treat the IP as "unknown" for rate limiting
        if (realIp == null) {
            realIp = "unknown";
            log.warn("[{}] Could not determine client IP; applying rate limits to 'unknown' IP", providerName);
        }

        // Hashes the IP for rate limiting
        String hashedIp = HashUtil.hashIp(realIp);

        // Invalid-request block lookup (no token consumed here)
        if (provider.isInvalidRequestBlocked(hashedIp)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // Burst rate limit lookup (consumes one token)
        if (RateLimitUtil.isBurstBlocked(provider, hashedIp, providerName)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // Sustained rate limit lookup (consumes one token)
        if (RateLimitUtil.isSustainedBlocked(provider, hashedIp, providerName)) {
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }
        return hashedIp;
    }

    /**
     * Normalizes a single client IP literal from servlet/proxy input.
     *
     * @param candidate The raw IP candidate.
     * @return A normalized IP literal, or {@code null} if invalid.
     */
    @Contract("null -> null")
    private static @Nullable String normalizeClientIp(@Nullable String candidate) {
        // Returns null for missing candidates
        if (candidate == null) {
            return null;
        }

        String ip = candidate.strip();

        // Rejects empty, excessively long, or comma-containing candidates
        if (ip.isEmpty()
                || ip.length() > MAX_IP_LITERAL_LENGTH
                || ip.indexOf(',') >= 0
                || !isValidIpLiteral(ip)) {
            return null;
        }
        return ip.toLowerCase(Locale.ROOT);
    }

    /**
     * Validates IPv4 and IPv6 literals without accepting hostnames.
     *
     * @param ip The candidate IP literal.
     * @return {@code true} if the candidate is a valid IP literal.
     */
    private static boolean isValidIpLiteral(@NonNull String ip) {
        // Quick check for valid IPv4 literals before the more expensive InetAddress parsing
        if (NetworkUtil.isDottedDecimalIpv4(ip)) {
            return true;
        }

        // Rejects candidates with characters invalid in IP literals or that contain IPv6 zone identifiers or brackets
        if (ip.indexOf(':') < 0
                || ip.indexOf('%') >= 0
                || ip.indexOf('[') >= 0
                || ip.indexOf(']') >= 0) {
            return false;
        }

        // Validates that all characters are valid in IPv4 or IPv6 literals
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);

            if (c != ':' && c != '.'
                    && !(c >= '0' && c <= '9')
                    && !(c >= 'a' && c <= 'f')
                    && !(c >= 'A' && c <= 'F')) {
                return false;
            }
        }

        // Uses InetAddress parsing as a final check to confirm the
        // candidate is a valid IP literal and not a hostname
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address instanceof Inet6Address || (address instanceof Inet4Address && ip.indexOf(':') >= 0);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
            return false;
        }
    }

    /**
     * Validates a request's JSON body and extracts the "url" field if present.
     *
     * @param bodyBytes The raw request body bytes to validate and parse.
     * @param provider The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp The hashed IP address of the sender for rate limiting purposes.
     * @return A map containing the extracted "url" field if present, or an empty map if not.
     */
    public static @NonNull @Unmodifiable Map<String, String> validateBody(byte[] bodyBytes, Provider provider,
                                                                          String providerName, String hashedIp) {
        byte[] bytes = (bodyBytes != null) ? bodyBytes : new byte[0];

        if (bytes.length == 0) {
            throw reject(provider, hashedIp, providerName, "Blocked request with empty body");
        }

        String url = null;

        try (JsonParser parser = JacksonUtil.MAPPER.createParser(bytes)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw reject(provider, hashedIp, providerName, "Blocked request with non-object JSON body");
            }

            int fieldCount = 0;
            JsonToken token;

            while ((token = parser.nextToken()) != JsonToken.END_OBJECT) {
                if (token != JsonToken.PROPERTY_NAME || ++fieldCount > 1) {
                    throw reject(provider, hashedIp, providerName, "Blocked request with unexpected fields");
                }

                String fieldName = parser.currentName();
                JsonToken valueToken = parser.nextToken();

                if (!"url".equals(fieldName)) {
                    throw reject(provider, hashedIp, providerName, "Blocked request with unexpected fields");
                }

                if (valueToken == JsonToken.VALUE_STRING) {
                    url = parser.getString();
                } else if (valueToken != JsonToken.VALUE_NULL) {
                    throw reject(provider, hashedIp, providerName,
                            "Blocked request with non-string url value: " + valueToken);
                }
            }

            // Reject trailing garbage after the closing brace (e.g. "{...}{...}")
            if (parser.nextToken() != null) {
                throw reject(provider, hashedIp, providerName, "Blocked request with trailing JSON content");
            }
        } catch (StatusCodeException e) {
            throw e; // includes the 429 that rejectInvalidRequest may raise
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            throw reject(provider, hashedIp, providerName,
                    "Blocked request with malformed JSON body (" + e.getClass().getName() + ")");
        }
        return url != null ? Map.of("url", url) : Map.of();
    }

    /**
     * Records the invalid request against the abuse limiter and returns a 400 to throw.
     * Note: rejectInvalidRequest may itself throw a 429 if the IP is over the limit.
     *
     * @param provider The provider to reject invalid requests with.
     * @param hashedIp The hashed client IP.
     * @param providerName The provider name.
     * @param message The rejection log message.
     * @return A StatusCodeException with a 400 response code to throw.
     */
    private static @NonNull StatusCodeException reject(Provider provider, String hashedIp,
                                                       String providerName, String message) {
        RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, message);
        return new StatusCodeException(ErrorUtil.RESP_400);
    }

    /**
     * Validates a request's URI.
     *
     * @param url          The raw URL string to validate.
     * @param provider     The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp     The hashed IP address of the sender.
     * @return A normalized URI object if the URL is valid.
     * @throws StatusCodeException If the URL is found to be invalid.
     */
    @SuppressWarnings({"ResultOfMethodCallIgnored", "NestedMethodCall"})
    public static URI validateURI(@NonNull String url, Provider provider, String providerName, String hashedIp) {
        // Rejects missing or empty URLs
        if (url.isBlank()) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "Blocked request with missing or empty URL");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Rejects excessively long URLs
        int length = url.length();
        if (length > 8192) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with excessively long URL (" + length + " characters)");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Normalizes and validates URL syntax
        URI parsedUri;
        try {
            String encoded = NetworkUtil.encodeIllegalUriChars(url);
            parsedUri = new URI(encoded).normalize();
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, "");
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }

        // Prepends https:// for schemeless URLs (e.g., "example.com" parses as a path, not a host)
        if (parsedUri.getScheme() == null) {
            try {
                parsedUri = new URI("https://" + parsedUri).normalize();
                parsedUri.toURL();
            } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with malformed URL (" + e.getClass().getName() + ")");
                throw new StatusCodeException(ErrorUtil.RESP_400);
            }
        }
        return parsedUri;
    }

    /**
     * Validates a request's scheme.
     *
     * @param parsedUri    The parsed URI object to take the scheme from.
     * @param provider     The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp     The hashed IP address of the sender.
     * @return The normalized scheme string if valid (e.g., "http" or "https").
     * @throws StatusCodeException If the scheme is found to be invalid.
     */
    public static @NonNull String validateScheme(@NonNull URI parsedUri, Provider provider,
                                                 String providerName, String hashedIp) {
        String scheme = parsedUri.getScheme().toLowerCase(Locale.ROOT);

        // Rejects unsupported schemes (only http and https allowed)
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                    "Blocked request with disallowed URL scheme '" + scheme);
            throw new StatusCodeException(ErrorUtil.RESP_400);
        }
        return scheme;
    }

    /**
     * Validates a request's host.
     *
     * @param parsedUri    The parsed URI object to take the host from.
     * @param provider     The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp     The hashed IP address of the sender.
     * @return The normalized host string if valid.
     * @throws StatusCodeException If the host is found to be invalid.
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull String validateHost(@NonNull URI parsedUri, Provider provider,
                                               String providerName, String hashedIp) {
        String host = parsedUri.getHost();

        // Extracts host from authority if getHost() is null
        if (host == null || host.isBlank()) {
            String authority = parsedUri.getRawAuthority();

            // Rejects requests with no authority/host component
            if (authority == null || authority.isBlank()) {
                rejectInvalidHost(provider, providerName, hashedIp, "Blocked request with no host");
                return "";
            }

            // Handles bracketed IPv6 literals (e.g., [::1] or [::1]:8080)
            if (authority.charAt(0) == '[' && authority.contains("]")) {
                int endIndex = authority.indexOf(']');
                host = authority.substring(1, endIndex);
            } else {
                int lastColon = authority.lastIndexOf(':');
                host = lastColon >= 0 ? authority.substring(0, lastColon) : authority;
            }
        }

        host = host.strip().toLowerCase(Locale.ROOT);

        // Strips surrounding brackets that URI.getHost() returns for IPv6 literals
        if (host.length() >= 2 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
            host = host.substring(1, host.length() - 1);
        }

        // Removes leading dot(s)
        while (!host.isBlank() && host.charAt(0) == '.') {
            host = host.substring(1);
        }

        // Removes trailing dot(s)
        while (!host.isBlank() && host.charAt(host.length() - 1) == '.') {
            host = host.substring(0, host.length() - 1);
        }

        // Rejects hosts that are empty after normalization
        if (host.isBlank()) {
            rejectInvalidHost(provider, providerName, hashedIp, "Blocked request with empty host");
        }

        // Rejects excessively long hosts
        if (host.length() > MAX_HOST_LENGTH) {
            rejectInvalidHost(provider, providerName, hashedIp,
                    "Blocked request with excessively long host (" + host.length() + " characters)");
        }

        // Handles IPv6 literals with colons without further processing
        if (host.indexOf(':') >= 0) {
            if (!NetworkUtil.isIpv6Literal(host)) {
                rejectInvalidHost(provider, providerName, hashedIp,
                        "Blocked request with invalid IPv6 literal host: '" + host + "'"
                );
            }
            return host;
        }

        // Rejects hosts without a . symbol
        if (!host.contains(".")) {
            rejectInvalidHost(provider, providerName, hashedIp, "");
        }

        // Returns IP literals as-is without IDN processing
        if (NetworkUtil.isIpLiteral(host)) {
            return host;
        }

        // Rejects private hosts
        if (NetworkUtil.isPrivateHost(host)) {
            rejectInvalidHost(provider, providerName, hashedIp, "Blocked request with private/internal host");
        }

        String asciiHost;

        // Converts the host to ASCII using IDN processing
        try {
            asciiHost = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            rejectInvalidHost(provider, providerName, hashedIp,
                    "Blocked request with invalid IDN host");
            return "";
        }

        // Rejects hosts that are empty after IDN normalization
        if (asciiHost.isBlank() || asciiHost.length() > MAX_HOST_LENGTH) {
            rejectInvalidHost(provider, providerName, hashedIp,
                    "Blocked request with invalid DNS host length");
        }

        // Rejects hosts without a . symbol after IDN normalization
        if (!asciiHost.contains(".")) {
            rejectInvalidHost(provider, providerName, hashedIp,
                    "Blocked request with host missing dot after IDN normalization");
        }

        String[] labels = asciiHost.split("\\.", -1);

        for (String label : labels) {
            // Rejects empty labels (e.g., consecutive dots or leading/trailing dot)
            if (label.isEmpty()) {
                rejectInvalidHost(provider, providerName, hashedIp,
                        "Blocked request with empty DNS label");
            }

            // Rejects labels that are too long
            if (label.length() > MAX_DNS_LABEL_LENGTH) {
                rejectInvalidHost(provider, providerName, hashedIp,
                        "Blocked request with oversized DNS label");
            }

            // Rejects labels that start or end with a hyphen
            if (label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') {
                rejectInvalidHost(provider, providerName, hashedIp,
                        "Blocked request with DNS label starting or ending with hyphen");
            }

            // Rejects labels with characters other than letters, digits, or hyphens
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);

                if (c != '-'
                        && !(c >= '0' && c <= '9')
                        && !(c >= 'a' && c <= 'z')) {
                    rejectInvalidHost(provider, providerName, hashedIp,
                            "Blocked request with invalid DNS label character");
                }
            }
        }
        return asciiHost;
    }

    /**
     * Rejects an invalid host and records the request against the invalid-request limiter.
     *
     * @param provider The provider to reject invalid requests with.
     * @param providerName The provider name.
     * @param hashedIp The hashed client IP.
     * @param message The rejection log message.
     */
    private static void rejectInvalidHost(@NonNull Provider provider,
                                          String providerName,
                                          String hashedIp,
                                          String message) {
        RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName, message);
        throw new StatusCodeException(ErrorUtil.RESP_400);
    }

    /**
     * Reconstructs a URI with the normalized host and scheme.
     *
     * @param parsedUri    The parsed URI to reconstruct from.
     * @param host         The normalized host.
     * @param scheme       The normalized scheme.
     * @param provider     The provider to reject invalid requests with.
     * @param providerName The name of the provider.
     * @param hashedIp     The hashed IP address of the sender.
     * @return The reconstructed URI.
     * @throws StatusCodeException If the port is found to be invalid.
     */
    @SuppressWarnings("NestedMethodCall")
    @Contract("_, _, _, _, _, _ -> new")
    public static @NonNull URI reconstructURI(@NonNull URI parsedUri, @NonNull String host, @NonNull String scheme,
                                              Provider provider, String providerName, String hashedIp) {
        // Reconstructs the URI with the normalized host and scheme
        try {
            int port = parsedUri.getPort();

            // Rejects ports outside the valid range (1-65535); -1 means no port specified
            if (port != -1 && (port < 1 || port > 65535)) {
                RateLimitUtil.rejectInvalidRequest(provider, hashedIp, providerName,
                        "Blocked request with invalid port: " + port);
                throw new StatusCodeException(ErrorUtil.RESP_400);
            }

            // Brackets IPv6 literal hosts so the authority is valid
            String authorityHost = host.indexOf(':') >= 0 ? ("[" + host + "]") : host;
            String authority = port == -1 ? authorityHost : (authorityHost + ":" + port);
            String rawPath = parsedUri.getRawPath();
            String rawQuery = parsedUri.getRawQuery();

            // Build from already-encoded (raw) components and parse with the single-arg
            // URI constructor, which preserves percent-escapes verbatim
            StringBuilder rebuilt = new StringBuilder(scheme.length() + authority.length() + 16)
                    .append(scheme).append("://").append(authority);

            if (rawPath != null) {
                rebuilt.append(rawPath);
            }

            if (rawQuery != null) {
                rebuilt.append('?').append(rawQuery);
            }
            return new URI(rebuilt.toString());
        } catch (StatusCodeException e) {
            throw e;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.error("[{}] Unexpected URI reconstruction failure: {} ({})",
                    providerName, e.getMessage(), e.getClass().getName());
            throw new StatusCodeException(ErrorUtil.RESP_502);
        }
    }
}
