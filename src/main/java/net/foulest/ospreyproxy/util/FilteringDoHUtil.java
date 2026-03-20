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
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
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
 * <p>
 * Each method mirrors the corresponding {@code checkUrlWith*} function in
 * {@code BrowserProtection.js}, returning {@code true} if the resolver considers
 * the host blocked and {@code false} otherwise. All methods are fail-open:
 * any I/O error, unexpected status code, bad content-type, or parse failure
 * returns {@code false} rather than throwing.
 * <p>
 * The five resolvers covered are:
 * <ul>
 *   <li>AdGuard Security DNS</li>
 *   <li>CleanBrowsing Security DNS</li>
 *   <li>Cloudflare Security DNS</li>
 *   <li>Quad9</li>
 *   <li>Switch.ch</li>
 * </ul>
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
    private static final String CT_DNS_MESSAGE = "application/dns-message";
    private static final String CT_DNS_JSON = "application/dns-json";

    // Block indicator IP for AdGuard Security (mirrors "94.140.14.33" in extension)
    private static final String ADGUARD_SECURITY_BLOCK_IP = "94.140.14.33";

    // Block indicator CNAME for Switch.ch (mirrors "landingpage.ph.rpz.switch.ch" in extension)
    private static final String SWITCH_CH_BLOCK_CNAME = "landingpage.ph.rpz.switch.ch";

    // Jackson mapper for Cloudflare JSON responses
    private static final ObjectMapper MAPPER = JsonMapper.builder().build();
    private static final JavaType MAP_TYPE = MAPPER.constructType(
            new TypeReference<Map<String, Object>>() {
            }
    );

    // Dedicated HTTP client for filtering DoH queries.
    // 5s connect + 5s response — aggressive, since executePhishingBox waits on all resolvers.
    private static final CloseableHttpClient FILTERING_CLIENT = HttpClients.custom()
            .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                    .setMaxConnTotal(100)
                    .setMaxConnPerRoute(20)
                    .setDefaultConnectionConfig(ConnectionConfig.custom()
                            .setConnectTimeout(Timeout.ofSeconds(5))
                            .build())
                    .build())
            .setDefaultRequestConfig(RequestConfig.custom()
                    .setConnectionRequestTimeout(Timeout.ofSeconds(5))
                    .setResponseTimeout(Timeout.ofSeconds(5))
                    .build())
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .build();

    // -------------------------------------------------------------------------
    // Public resolver methods
    // -------------------------------------------------------------------------

    /**
     * Queries AdGuard Security DNS for the given host.
     * <p>
     * Blocked when any A record in the answer section resolves to {@code 94.140.14.33}.
     * Mirrors {@code checkUrlWithAdGuardSecurity} in {@code BrowserProtection.js}.
     *
     * @param host The hostname to check (e.g., {@code "example.com"}).
     * @return {@code true} if AdGuard Security considers the host malicious, {@code false} otherwise.
     */
    public static boolean checkAdGuardSecurity(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDnsMessage(ADGUARD_SECURITY_URL + encoded, "AdGuard Security");

            if (response == null) {
                return false;
            }

            // Walk every A record in the answer section; blocked if rdata == 94.140.14.33
            return walkAnswers(response, (type, rdata) -> {
                if (type == DnsRRType.A) {
                    String ip = parseIPv4(rdata);
                    return ADGUARD_SECURITY_BLOCK_IP.equals(ip);
                }
                return false;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.debug("[AdGuard Security] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Queries CleanBrowsing Security DNS for the given host.
     * <p>
     * Blocked when byte index 3 of the raw response equals {@code 131} (RCODE REFUSED / block flag).
     * Mirrors {@code checkUrlWithCleanBrowsingSecurity} in {@code BrowserProtection.js}.
     *
     * @param host The hostname to check.
     * @return {@code true} if CleanBrowsing Security considers the host malicious, {@code false} otherwise.
     */
    public static boolean checkCleanBrowsingSecurity(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDnsMessage(CLEANBROWSING_SECURITY_URL + encoded, "CleanBrowsing Security");

            if (response == null) {
                return false;
            }

            // Blocked if response[3] == 131 (0x83: QR=1, RCODE=3 NXDOMAIN with AA set — CleanBrowsing's block signal)
            return response.length >= 4 && (response[3] & 0xFF) == 131;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.debug("[CleanBrowsing Security] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Queries Cloudflare Security DNS for the given host using the JSON DoH endpoint.
     * <p>
     * Blocked when the response contains a {@code Comment} field with the substring
     * {@code "EDE(16): Censored"}.
     * Mirrors {@code checkUrlWithCloudflareSecurity} in {@code BrowserProtection.js}.
     *
     * @param host The hostname to check.
     * @return {@code true} if Cloudflare Security considers the host blocked, {@code false} otherwise.
     */
    public static boolean checkCloudflareSecurity(@NonNull String host) {
        try {
            String encodedHost = DNSWireUtil.encodeHostParam(host);
            String url = CLOUDFLARE_SECURITY_URL + encodedHost;

            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", CT_DNS_JSON);

            return FILTERING_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.debug("[Cloudflare Security] Unexpected status {} for host '{}'", statusCode, host);
                    return false;
                }

                String contentType = getContentType(response);

                if (!contentType.contains(CT_DNS_JSON)) {
                    log.debug("[Cloudflare Security] Unexpected Content-Type '{}' for host '{}'", contentType, host);
                    return false;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity);

                if (body == null || body.length == 0) {
                    log.debug("[Cloudflare Security] Empty response body for host '{}'", host);
                    return false;
                }

                Map<String, Object> data;
                try {
                    data = MAPPER.readValue(body, MAP_TYPE);
                } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
                    log.debug("[Cloudflare Security] Failed to parse response JSON for host '{}': {}", host, e.getMessage());
                    return false;
                }

                Object comment = data.get("Comment");
                return comment instanceof String value && value.contains("EDE(16): Censored");
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.debug("[Cloudflare Security] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Queries Quad9 for the given host.
     * <p>
     * Blocked when byte index 3 of the raw response equals {@code 3} (RCODE NXDOMAIN — Quad9's block signal).
     * Mirrors {@code checkUrlWithQuad9} in {@code BrowserProtection.js}.
     *
     * @param host The hostname to check.
     * @return {@code true} if Quad9 considers the host malicious, {@code false} otherwise.
     */
    public static boolean checkQuad9(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDnsMessage(QUAD9_URL + encoded, "Quad9");

            if (response == null) {
                return false;
            }

            // Blocked if response[3] == 3 (RCODE NXDOMAIN — Quad9 returns NXDOMAIN for blocked hosts)
            return response.length >= 4 && (response[3] & 0xFF) == 3;
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.debug("[Quad9] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    /**
     * Queries Switch.ch Security DNS for the given host.
     * <p>
     * Blocked when any CNAME record in the answer section resolves to
     * {@code landingpage.ph.rpz.switch.ch} (case-insensitive, trailing-dot-stripped).
     * Mirrors {@code checkUrlWithSwitchCH} in {@code BrowserProtection.js}.
     *
     * @param host The hostname to check.
     * @return {@code true} if Switch.ch considers the host malicious, {@code false} otherwise.
     */
    public static boolean checkSwitchCH(@NonNull String host) {
        try {
            String encoded = DNSWireUtil.buildBase64Query(host);
            byte[] response = fetchDnsMessage(SWITCH_CH_URL + encoded, "Switch.ch");

            if (response == null) {
                return false;
            }

            // Walk every CNAME in the answer section; blocked if rdata == landingpage.ph.rpz.switch.ch
            return walkAnswers(response, (type, rdata) -> {
                if (type == DnsRRType.CNAME) {
                    String cname = parseName(rdata);
                    return SWITCH_CH_BLOCK_CNAME.equalsIgnoreCase(normalizeName(cname));
                }
                return false;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.debug("[Switch.ch] Failed to check host '{}': {} ({})", host, e.getMessage(), e.getClass().getName());
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Fetches the raw bytes of a {@code application/dns-message} response.
     * Returns {@code null} on any error (non-200, wrong content-type, empty body).
     */
    private static byte @Nullable [] fetchDnsMessage(@NonNull String url, @NonNull String resolverName) {
        try {
            HttpGet request = new HttpGet(url);
            request.addHeader("Accept", CT_DNS_MESSAGE);

            return FILTERING_CLIENT.execute(request, response -> {
                int statusCode = response.getCode();

                if (statusCode != 200) {
                    log.debug("[{}] Unexpected status {} for URL '{}'", resolverName, statusCode, url);
                    return null;
                }

                String contentType = getContentType(response);

                if (!contentType.contains(CT_DNS_MESSAGE)) {
                    log.debug("[{}] Unexpected Content-Type '{}' for URL '{}'", resolverName, contentType, url);
                    return null;
                }

                HttpEntity entity = response.getEntity();
                byte[] body = EntityUtils.toByteArray(entity);

                if (body == null || body.length == 0) {
                    log.debug("[{}] Empty response body for URL '{}'", resolverName, url);
                    return null;
                }

                return body;
            });
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.debug("[{}] HTTP fetch failed for URL '{}': {} ({})", resolverName, url, e.getMessage(), e.getClass().getName());
            return null;
        }
    }

    /**
     * Extracts the Content-Type header value from an HTTP response, defaulting to an empty string.
     */
    private static @NonNull String getContentType(@NonNull ClassicHttpResponse response) {
        Header header = response.getFirstHeader("Content-Type");
        return header != null ? header.getValue() : "";
    }

    /**
     * Walks the answer section of a raw DNS wire-format response, invoking the given
     * predicate for each resource record. Returns {@code true} as soon as the predicate
     * returns {@code true} for any record.
     * <p>
     * Only the answer section is walked — same scope as the extension's per-provider checks.
     *
     * @param response The raw DNS wire-format response bytes.
     * @param predicate A function receiving (rrType, rdataBytes) and returning true if blocked.
     * @return {@code true} if any answer record satisfies the predicate.
     */
    private static boolean walkAnswers(byte @NonNull [] response, @NonNull RRPredicate predicate) {
        // DNS header is 12 bytes. Minimum viable response with 0 answers is 12 bytes.
        if (response.length < 12) {
            return false;
        }

        int anCount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);

        if (anCount == 0 || anCount > 1000) {
            return false;
        }

        int off = 12;

        // Skip the question section: read QDCOUNT questions
        int qdCount = ((response[4] & 0xFF) << 8) | (response[5] & 0xFF);
        for (int i = 0; i < qdCount; i++) {
            off = skipName(response, off);
            off += 4; // QTYPE (2) + QCLASS (2)

            if (off > response.length) {
                return false;
            }
        }

        // Read each answer RR
        for (int i = 0; i < anCount; i++) {
            if (off >= response.length) {
                break;
            }

            // Skip owner name
            off = skipName(response, off);
            if (off + 10 > response.length) {
                break;
            }

            int rrType = ((response[off] & 0xFF) << 8) | (response[off + 1] & 0xFF);
            // skip TYPE(2) + CLASS(2) + TTL(4)
            off += 8;

            int rdLength = ((response[off] & 0xFF) << 8) | (response[off + 1] & 0xFF);
            off += 2;

            if (off + rdLength > response.length) {
                break;
            }

            byte[] rdata = new byte[rdLength];
            System.arraycopy(response, off, rdata, 0, rdLength);
            off += rdLength;

            // Pass the full packet and rdata start offset so name parsing can follow compression pointers
            if (predicate.test(rrType, rdata)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Skips a DNS name (label sequence or compression pointer) at {@code off},
     * returning the offset of the first byte after the name.
     */
    @Contract(pure = true)
    private static int skipName(byte @NonNull [] data, int off) {
        while (off < data.length) {
            int len = data[off] & 0xFF;

            if ((len & 0xC0) == 0xC0) {
                // Compression pointer: 2 bytes, then we're done advancing the outer cursor
                off += 2;

                // After a pointer the outer cursor has been advanced; stop here
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
     * Parses an IPv4 address from 4 raw RDATA bytes.
     * Returns {@code null} if the array is not exactly 4 bytes.
     */
    @Contract(pure = true)
    private static @Nullable String parseIPv4(byte @NonNull [] rdata) {
        if (rdata.length != 4) {
            return null;
        }
        return (rdata[0] & 0xFF) + "." + (rdata[1] & 0xFF) + "." + (rdata[2] & 0xFF) + "." + (rdata[3] & 0xFF);
    }

    /**
     * Parses a domain name from RDATA that holds a DNS wire-format name.
     * Handles compression pointers relative to the outer packet buffer if needed;
     * since CNAME rdata is self-contained here we just read labels sequentially.
     * Returns an empty string on any parse failure.
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

            // Compression pointers inside isolated rdata bytes cannot be resolved;
            // treat as end-of-name
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
     * Normalizes a DNS name for comparison: lower-cased, trailing dot stripped.
     * Mirrors {@code DNSMessage.normalizeName()} in the extension.
     */
    private static @NonNull String normalizeName(@NonNull String name) {
        String n = name.trim().toLowerCase(Locale.ROOT);
        return !n.isEmpty() && n.charAt(n.length() - 1) == '.' ? n.substring(0, n.length() - 1) : n;
    }

    // -------------------------------------------------------------------------
    // DNS RR type constants (subset used by FilteringDoHUtil)
    // -------------------------------------------------------------------------

    private static final class DnsRRType {

        static final int A = 1;
        static final int CNAME = 5;
    }

    // -------------------------------------------------------------------------
    // Internal functional interface for RR predicate
    // -------------------------------------------------------------------------

    @FunctionalInterface
    private interface RRPredicate {

        boolean test(int rrType, byte[] rdata);
    }
}
