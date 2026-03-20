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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.util.Timeout;
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;

/**
 * Executes filtering DNS-over-HTTPS lookups against each security resolver used by PhishingBox.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class FilteringDoHUtil {

    // Resolver endpoints
    private static final String ADGUARD_SECURITY_URL = "https://dns.adguard-dns.com/dns-query?dns=";
    private static final String CLEANBROWSING_SECURITY_URL = "https://doh.cleanbrowsing.org/doh/security-filter/dns-query?dns=";
    private static final String CLOUDFLARE_SECURITY_URL = "https://security.cloudflare-dns.com/dns-query?name=";
    private static final String QUAD9_URL = "https://dns.quad9.net/dns-query?dns=";
    private static final String SWITCH_CH_URL = "https://dns.switch.ch/dns-query?dns=";

    // Content-type header values
    private static final String DNS_MESSAGE = "application/dns-message";
    private static final String DNS_JSON = "application/dns-json";

    // Jackson mapper for Cloudflare JSON responses
    private static final ObjectMapper MAPPER = JsonMapper.builder().build();
    private static final JavaType MAP_TYPE = MAPPER.constructType(
            new TypeReference<Map<String, Object>>() {
            }
    );

    // HTTP/2 client for filtering DoH queries
    private static final CloseableHttpClient FILTERING_CLIENT;

    static {
        CloseableHttpAsyncClient asyncClient = HttpAsyncClients.customHttp2()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(5))
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                        .setResponseTimeout(Timeout.ofSeconds(5))
                        .build())
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .build();

        asyncClient.start();
        FILTERING_CLIENT = HttpAsyncClients.classic(asyncClient, Timeout.ofSeconds(10));
    }

    /**
     * Checks a hostname with AdGuard's filtering DNS server.
     *
     * @param host The host to check, e.g. "example.com".
     * @return Whether the host is blocked by the provider.
     */
    public static boolean checkWithAdGuard(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDNSMessage(ADGUARD_SECURITY_URL + encoded, "AdGuard Security");

            if (response == null) {
                log.warn("[AdGuard] Null response returned for '{}'", host);
                return false;
            }

            return walkAnswers(response, (type, rdata) -> {
                if (type == DnsRRType.A) {
                    String ip = parseIPv4(rdata);

                    if (ip == null) {
                        return false;
                    }
                    return ip.equals("94.140.14.33");
                }
                return false;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[AdGuard] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Checks a hostname with CleanBrowsing's filtering DNS server.
     *
     * @param host The host to check, e.g. "example.com".
     * @return Whether the host is blocked by the provider.
     */
    public static boolean checkWithCleanBrowsing(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDNSMessage(CLEANBROWSING_SECURITY_URL + encoded, "CleanBrowsing Security");

            if (response == null) {
                log.warn("[CleanBrowsing] Null response returned for '{}'", host);
                return false;
            }
            return response.length >= 4 && (response[3] & 0xFF) == 131;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[CleanBrowsing] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Checks a hostname with Cloudflare's filtering DNS server.
     *
     * @param host The host to check, e.g. "example.com".
     * @return Whether the host is blocked by the provider.
     */
    public static boolean checkWithCloudflare(@NonNull String host) {
        try {
            String encodedHost = DNSWireUtil.encodeHostParam(host);
            String url = CLOUDFLARE_SECURITY_URL + encodedHost;

            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", DNS_JSON);

            return FILTERING_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.warn("[Cloudflare Security] Unexpected status {} for host '{}'", statusCode, host);
                    return false;
                }

                String contentType = getContentType(response);

                if (!contentType.contains(DNS_JSON)) {
                    log.warn("[Cloudflare Security] Unexpected Content-Type '{}' for host '{}'", contentType, host);
                    return false;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity);

                if (body == null || body.length == 0) {
                    log.warn("[Cloudflare Security] Empty response body for host '{}'", host);
                    return false;
                }

                Map<String, Object> data;

                try {
                    data = MAPPER.readValue(body, MAP_TYPE);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.warn("[Cloudflare Security] Failed to parse response JSON for host '{}': {}", host, e.getMessage());
                    return false;
                }

                Object comment = data.get("Comment");
                return comment instanceof String value && value.contains("EDE(16): Censored");
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[Cloudflare Security] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Checks a hostname with Quad9's filtering DNS server.
     *
     * @param host The host to check, e.g. "example.com".
     * @return Whether the host is blocked by the provider.
     */
    public static boolean checkWithQuad9(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDNSMessage(QUAD9_URL + encoded, "Quad9");

            if (response == null) {
                log.warn("[Quad9] Null response returned for '{}'", host);
                return false;
            }
            return response.length >= 4 && (response[3] & 0xFF) == 3;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[Quad9] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Checks a hostname with Switch.ch's filtering DNS server.
     *
     * @param host The host to check, e.g. "example.com".
     * @return Whether the host is blocked by the provider.
     */
    public static boolean checkWithSwitchCH(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDNSMessage(SWITCH_CH_URL + encoded, "Switch.ch");

            if (response == null) {
                log.warn("[Switch.ch] Null response returned for '{}'", host);
                return false;
            }

            return walkAnswers(response, (type, rdata) -> {
                if (type == DnsRRType.CNAME) {
                    String cname = parseName(rdata);
                    return normalizeName(cname).equalsIgnoreCase("landingpage.ph.rpz.switch.ch");
                }
                return false;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[Switch.ch] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Fetches a DNS message from the given URL and returns the raw response bytes.
     *
     * @param url The full URL to fetch.
     * @param resolverName The name of the resolver for logging purposes.
     */
    private static byte @Nullable [] fetchDNSMessage(@NonNull String url, @NonNull String resolverName) {
        try {
            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", DNS_MESSAGE);

            return FILTERING_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.warn("[{}] Unexpected status {} for URL '{}'", resolverName, statusCode, url);
                    return null;
                }

                String contentType = getContentType(response);

                if (!contentType.contains(DNS_MESSAGE)) {
                    log.warn("[{}] Unexpected Content-Type '{}' for URL '{}'", resolverName, contentType, url);
                    return null;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity);

                if (body == null || body.length == 0) {
                    log.warn("[{}] Empty response body for URL '{}'", resolverName, url);
                    return null;
                }
                return body;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] HTTP fetch failed for URL '{}': {} ({})", resolverName, url, e.getMessage(), e.getClass().getName());
            return null;
        }
    }

    /**
     * Extracts the Content-Type header value from the response.
     *
     * @param response The response to extract the Content-Type from.
     * @return The Content-Type as a String.
     */
    private static @NonNull String getContentType(@NonNull ClassicHttpResponse response) {
        Header header = response.getFirstHeader("Content-Type");
        return header != null ? header.getValue() : "";
    }

    /**
     * Walks through the answer records in the raw DNS message response
     * and tests each record against the given predicate.
     *
     * @param response The raw DNS message response bytes.
     * @param predicate The predicate to test each answer record against. Takes the RR type and RDATA bytes as input.
     * @return {@code true} if any answer record matches the predicate, {@code false} otherwise or if the response is malformed.
     */
    private static boolean walkAnswers(byte @NonNull [] response, @NonNull RRPredicate predicate) {
        if (response.length < 12) {
            return false;
        }

        int anCount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);

        if (anCount == 0 || anCount > 1000) {
            return false;
        }

        int off = 12;
        int qdCount = ((response[4] & 0xFF) << 8) | (response[5] & 0xFF);

        for (int i = 0; i < qdCount; i++) {
            off = skipName(response, off);
            off += 4;

            if (off > response.length) {
                return false;
            }
        }

        for (int i = 0; i < anCount; i++) {
            if (off >= response.length) {
                break;
            }

            off = skipName(response, off);

            if (off + 10 > response.length) {
                break;
            }

            int rrType = ((response[off] & 0xFF) << 8) | (response[off + 1] & 0xFF);
            off += 8;

            int rdLength = ((response[off] & 0xFF) << 8) | (response[off + 1] & 0xFF);
            off += 2;

            if (off + rdLength > response.length) {
                break;
            }

            byte[] rdata = new byte[rdLength];
            System.arraycopy(response, off, rdata, 0, rdLength);
            off += rdLength;

            if (predicate.test(rrType, rdata)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Skips over a domain name in the raw DNS message bytes, starting at the given offset.
     *
     * @param data The raw byte array of the DNS message.
     * @param off The offset to start skipping from. Should point to the beginning of a domain name (QNAME or NAME field).
     * @return The offset immediately after the domain name. Handles both uncompressed and compressed names.
     *         Returns an offset beyond the array length if the name is malformed.
     */
    @Contract(pure = true)
    private static int skipName(byte @NonNull [] data, int off) {
        while (off < data.length) {
            int len = data[off] & 0xFF;

            if ((len & 0xC0) == 0xC0) {
                off += 2;
                break;
            }

            if (len == 0) {
                off += 1;
                break;
            }

            off += 1 + len;
        }
        return off;
    }

    /**
     * Parses an IPv4 address from the given RDATA bytes. Expects exactly 4 bytes for a valid IPv4 address.
     *
     * @param rdata The raw RDATA bytes from an A record.
     * @return The IPv4 address in dotted-decimal notation (e.g. "192.168.1.1")
     */
    @Contract(pure = true)
    private static @Nullable String parseIPv4(byte @NonNull [] rdata) {
        if (rdata.length != 4) {
            return null;
        }
        return (rdata[0] & 0xFF) + "." + (rdata[1] & 0xFF) + "." + (rdata[2] & 0xFF) + "." + (rdata[3] & 0xFF);
    }

    /**
     * Parses a domain name from the given RDATA bytes. Handles uncompressed names only, as expected in CNAME RDATA.
     *
     * @param rdata The raw RDATA bytes from a CNAME record, which should contain the domain name in DNS label format.
     *              Compression pointers are not expected in RDATA.
     * @return The parsed domain name as a String, without the trailing dot.
     *         Returns an empty string if the RDATA is malformed.
     */
    private static @NonNull String parseName(byte @NonNull [] rdata) {
        StringBuilder sb = new StringBuilder();
        int off = 0;
        boolean first = true;

        while (off < rdata.length) {
            int len = rdata[off] & 0xFF;

            if (len == 0) {
                break;
            }

            if ((len & 0xC0) == 0xC0) {
                break;
            }

            off++;

            if (off + len > rdata.length) {
                break;
            }

            if (!first) {
                sb.append('.');
            }

            sb.append(new String(rdata, off, len, StandardCharsets.UTF_8));
            off += len;
            first = false;
        }
        return sb.toString();
    }

    /**
     * Normalizes a domain name by trimming whitespace, converting to lowercase, and removing any trailing dots.
     *
     * @param name The domain name to normalize.
     * @return The normalized domain name, suitable for case-insensitive comparison.
     *         For example, "Example.COM. " becomes "example.com".
     */
    private static @NonNull String normalizeName(@NonNull String name) {
        String n = name.trim().toLowerCase(Locale.ROOT);
        return !n.isEmpty() && n.charAt(n.length() - 1) == '.' ? n.substring(0, n.length() - 1) : n;
    }

    /**
     * DNS RR type constants for the record types we care about in filtering responses.
     */
    private static final class DnsRRType {

        static final int A = 1;
        static final int CNAME = 5;
    }

    /**
     * Functional interface for testing DNS answer records in the raw response bytes.
     * The predicate takes the RR type and RDATA bytes as input and returns a boolean
     * indicating whether the record matches the filtering criteria.
     */
    @FunctionalInterface
    private interface RRPredicate {

        boolean test(int rrType, byte[] rdata);
    }
}
