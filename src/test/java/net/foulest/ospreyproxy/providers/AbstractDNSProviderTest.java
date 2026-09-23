/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
package net.foulest.ospreyproxy.providers;

import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.services.CircuitBreakerService;
import net.foulest.ospreyproxy.util.dns.DNSFormat;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.assertj.core.api.Assertions;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Tests {@link AbstractDNSProvider}. The real fetch/parse paths (success, error statuses, malformed
 * responses, connection failures) are exercised through a mocked {@link CloseableHttpClient} rather
 * than a real socket, since {@code NetworkUtil.DNS_RESOLVER} deliberately blocks connections to
 * loopback/private addresses (SSRF protection), which would make a local test server unreachable.
 */
class AbstractDNSProviderTest {

    private static class TestDnsProvider extends AbstractDNSProvider {

        private final DNSFormat format;
        private final CloseableHttpClient httpClient;

        TestDnsProvider(CircuitBreakerService circuitBreakerService, DNSFormat format, CloseableHttpClient httpClient) {
            super(circuitBreakerService);
            this.format = format;
            this.httpClient = httpClient;
        }

        @Override
        public @NonNull String getDisplayName() {
            return "TestDNS";
        }

        @Override
        public @NonNull String getEndpointName() {
            return "testdns";
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public @NonNull String getApiUrl() {
            return "http://dns.test.invalid/";
        }

        @Override
        protected DNSFormat getDnsFormat() {
            return format;
        }

        @Override
        protected @NonNull CloseableHttpClient getDnsHttpClient() {
            return httpClient;
        }

        @Override
        protected LookupResult interpret(byte[] rawBytes, Map<String, Object> jsonResponse) {
            if (rawBytes != null) {
                return rawBytes.length > 0 ? LookupResult.MALICIOUS : LookupResult.FAILED;
            }
            return jsonResponse != null && !jsonResponse.isEmpty() ? LookupResult.MALICIOUS : LookupResult.FAILED;
        }
    }

    private static class DefaultFormatDnsProvider extends AbstractDNSProvider {

        DefaultFormatDnsProvider(CircuitBreakerService circuitBreakerService) {
            super(circuitBreakerService);
        }

        @Override
        public @NonNull String getDisplayName() {
            return "DefaultFormatDNS";
        }

        @Override
        public @NonNull String getEndpointName() {
            return "defaultformatdns";
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        protected LookupResult interpret(byte[] rawBytes, Map<String, Object> jsonResponse) {
            return LookupResult.FAILED;
        }
    }

    private static final class BranchDnsProvider extends TestDnsProvider {

        BranchDnsProvider(CircuitBreakerService circuitBreakerService, CloseableHttpClient client, DNSFormat format) {
            super(circuitBreakerService, format, client);
        }

        @Override
        public @NonNull String getDisplayName() {
            return "BranchDNS";
        }
    }

    private static final class LegacyDnsProvider extends AbstractDNSProvider {

        LegacyDnsProvider(CircuitBreakerService circuitBreakerService) {
            super(circuitBreakerService);
        }

        @Override
        public @NonNull String getDisplayName() {
            return "LegacyDNS";
        }

        @Override
        public @NonNull String getEndpointName() {
            return "legacy-dns";
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public boolean isUsingOldHTTP() {
            return true;
        }

        @Override
        protected LookupResult interpret(byte[] rawBytes, Map<String, Object> jsonResponse) {
            return LookupResult.FAILED;
        }
    }

    private final CircuitBreakerService circuitBreakerService = Mockito.mock(CircuitBreakerService.class);

    private static CloseableHttpClient mockClientReturning(int statusCode, String contentType, byte[] body) throws IOException {
        BasicClassicHttpResponse response = new BasicClassicHttpResponse(statusCode);

        if (contentType != null) {
            response.addHeader("Content-Type", contentType);
            response.setEntity(new ByteArrayEntity(body, ContentType.parse(contentType)));
        } else {
            response.setEntity(new ByteArrayEntity(body, null));
        }

        return mockClientHandling(response);
    }

    private static CloseableHttpClient mockClientReturningStreamThatFails(String contentType) throws IOException {
        BasicClassicHttpResponse response = new BasicClassicHttpResponse(200);
        response.addHeader("Content-Type", contentType);

        InputStream failingStream = new InputStream() {
            private int position;

            @Override
            public int read() throws IOException {
                if (position < 2) {
                    position++;
                    return 0x01;
                }
                throw new IOException("simulated mid-stream read failure");
            }
        };
        response.setEntity(new InputStreamEntity(failingStream, ContentType.parse(contentType)));

        return mockClientHandling(response);
    }

    @SuppressWarnings("unchecked")
    private static CloseableHttpClient mockClientHandling(BasicClassicHttpResponse response) throws IOException {
        CloseableHttpClient client = Mockito.mock(CloseableHttpClient.class);
        Mockito.when(client.execute(ArgumentMatchers.any(ClassicHttpRequest.class),
                        ArgumentMatchers.<HttpClientResponseHandler<Object>>any()))
                .thenAnswer(invocation -> {
                    HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
                    return handler.handleResponse(response);
                });
        return client;
    }

    private static CloseableHttpClient mockClientThrowing(IOException exception) throws IOException {
        CloseableHttpClient client = Mockito.mock(CloseableHttpClient.class);
        Mockito.when(client.execute(ArgumentMatchers.any(ClassicHttpRequest.class),
                        ArgumentMatchers.<HttpClientResponseHandler<Object>>any()))
                .thenThrow(exception);
        return client;
    }

    // --- getDnsFormat ---

    @Test
    void getDnsFormatDefaultsToPathMessage() {
        DefaultFormatDnsProvider provider = new DefaultFormatDnsProvider(circuitBreakerService);
        Assertions.assertThat(provider.getDnsFormat()).isEqualTo(DNSFormat.PATH_MESSAGE);
    }

    // --- extractComment ---

    @Test
    void extractCommentReturnsEmptyWhenCommentIsMissing() {
        Assertions.assertThat(AbstractDNSProvider.extractComment(Map.of())).isEmpty();
    }

    @Test
    void extractCommentReturnsStringWhenCommentIsAString() {
        Map<String, Object> json = Map.of("Comment", "hello");
        Assertions.assertThat(AbstractDNSProvider.extractComment(json)).isEqualTo("hello");
    }

    @Test
    void extractCommentJoinsListWhenCommentIsAList() {
        Map<String, Object> json = Map.of("Comment", List.of("a", "b"));
        Assertions.assertThat(AbstractDNSProvider.extractComment(json)).isEqualTo("a b");
    }

    @Test
    void extractCommentReturnsEmptyWhenCommentIsUnexpectedType() {
        Map<String, Object> json = Map.of("Comment", 42);
        Assertions.assertThat(AbstractDNSProvider.extractComment(json)).isEmpty();
    }

    // --- getDnsHttpClient ---

    @Test
    void getDnsHttpClientDefaultsToSharedClientForModernProviders() {
        DefaultFormatDnsProvider provider = new DefaultFormatDnsProvider(circuitBreakerService);
        Assertions.assertThat(provider.getDnsHttpClient()).isNotNull();
    }

    // --- lookupAndCache: circuit breaker open ---

    @Test
    void lookupAndCacheReturnsRateLimitedWhenCircuitBreakerIsOpen() throws IOException {
        Mockito.when(circuitBreakerService.isOpen("TestDNS")).thenReturn(true);
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(200, "application/dns-message", new byte[]{0x01}));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.RATE_LIMITED);
        Mockito.verify(circuitBreakerService, Mockito.never()).recordFailure(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
        Mockito.verify(circuitBreakerService, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong());
    }

    // --- lookup: invalid host triggers DNSUtil validation exception (outer catch) ---

    @Test
    void lookupAndCacheReturnsFailedWhenHostIsInvalidForNameFormat() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.NAME_JSON,
                mockClientReturning(200, "application/dns-json", new byte[]{0x01}));

        LookupVerdict verdict = provider.lookupAndCache("bad host!");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService, Mockito.never()).recordFailure(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
        Mockito.verify(circuitBreakerService, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong());
    }

    // --- fetchBytes / lookup: wire-message format (PATH_MESSAGE) ---

    @Test
    void lookupAndCacheReturnsInterpretedResultOnSuccessfulMessageResponse() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(200, "application/dns-message", new byte[]{0x01, 0x02, 0x03}));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.of(LookupResult.MALICIOUS));
        Assertions.assertThat(provider.getCachedResult("example.com")).isEqualTo(LookupVerdict.of(LookupResult.MALICIOUS));
        Mockito.verify(circuitBreakerService).recordSuccess(ArgumentMatchers.eq("TestDNS"), ArgumentMatchers.anyLong());
    }

    @Test
    void lookupAndCacheReturnsFailedWhenMessageResponseBodyIsEmpty() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(200, "application/dns-message", new byte[0]));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong());
        Mockito.verify(circuitBreakerService, Mockito.never()).recordFailure(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
    }

    // --- fetchBytes: non-200 statuses ---

    @Test
    void lookupAndCacheRecordsFailureOn429Response() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(429, "text/plain", new byte[0]));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService).recordFailure(ArgumentMatchers.eq("TestDNS"), ArgumentMatchers.eq(0L), ArgumentMatchers.any());
    }

    @Test
    void lookupAndCacheRecordsFailureOn500Response() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(500, "text/plain", new byte[0]));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService).recordFailure(ArgumentMatchers.eq("TestDNS"), ArgumentMatchers.eq(0L), ArgumentMatchers.any());
    }

    @Test
    void lookupAndCacheDoesNotRecordFailureOnOtherErrorStatus() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(403, "text/plain", new byte[0]));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService, Mockito.never()).recordFailure(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
        Mockito.verify(circuitBreakerService, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong());
    }

    // --- fetchBytes: content-type mismatch ---

    @Test
    void lookupAndCacheReturnsFailedWhenContentTypeDoesNotMatch() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturning(200, "text/html", new byte[]{0x01}));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong());
        Mockito.verify(circuitBreakerService, Mockito.never()).recordFailure(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
    }

    // --- fetchBytes: IOException while reading the body ---

    @Test
    void lookupAndCacheReturnsFailedWhenBodyReadFailsMidStream() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientReturningStreamThatFails("application/dns-message"));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong());
        Mockito.verify(circuitBreakerService, Mockito.never()).recordFailure(ArgumentMatchers.anyString(), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
    }

    // --- fetchBytes: client-level failure (outer catch) ---

    @Test
    void lookupAndCacheRecordsFailureWhenClientThrows() throws IOException {
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_MESSAGE,
                mockClientThrowing(new ConnectException("Connection refused")));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreakerService).recordFailure(ArgumentMatchers.eq("TestDNS"), ArgumentMatchers.anyLong(), ArgumentMatchers.any());
    }

    // --- fetchDnsJson: JSON format (NAME_JSON / PATH_JSON) ---

    @Test
    void lookupAndCacheReturnsInterpretedResultOnSuccessfulJsonResponse() throws IOException {
        byte[] body = "{\"Comment\":\"blocked\"}".getBytes(StandardCharsets.UTF_8);
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.PATH_JSON,
                mockClientReturning(200, "application/dns-json", body));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.of(LookupResult.MALICIOUS));
        Mockito.verify(circuitBreakerService).recordSuccess(ArgumentMatchers.eq("TestDNS"), ArgumentMatchers.anyLong());
    }

    @Test
    void lookupAndCacheReturnsFailedWhenJsonBodyIsUnparseable() throws IOException {
        byte[] body = "not json".getBytes(StandardCharsets.UTF_8);
        TestDnsProvider provider = new TestDnsProvider(circuitBreakerService, DNSFormat.NAME_JSON,
                mockClientReturning(200, "application/dns-json", body));

        LookupVerdict verdict = provider.lookupAndCache("example.com");

        Assertions.assertThat(verdict).isEqualTo(LookupVerdict.FAILED);
    }

    // --- static closeSharedClients ---

    @Test
    void closeSharedClientsIsIdempotent() {
        Assertions.assertThatCode(AbstractDNSProvider::closeSharedClients).doesNotThrowAnyException();
        // Second call must be a no-op (compareAndSet guard already tripped).
        Assertions.assertThatCode(AbstractDNSProvider::closeSharedClients).doesNotThrowAnyException();
    }

    @Test
    void usesTheLegacySharedClientWhenRequested() {
        Assertions.assertThat(new LegacyDnsProvider(Mockito.mock(CircuitBreakerService.class)).getDnsHttpClient()).isNotNull();
    }

    @Test
    void rejectsJsonRequestsWhenFetchReturnsNoBody() throws IOException {
        CircuitBreakerService circuitBreaker = Mockito.mock(CircuitBreakerService.class);
        BranchDnsProvider provider = new BranchDnsProvider(circuitBreaker,
                clientHandling(response(500, "text/plain", new byte[0])), DNSFormat.NAME_JSON);

        Assertions.assertThat(provider.lookupAndCache("example.com")).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreaker).recordFailure(ArgumentMatchers.eq("BranchDNS"), ArgumentMatchers.eq(0L),
                ArgumentMatchers.any());
    }

    @Test
    void rejectsResponsesWithoutAContentTypeHeader() throws IOException {
        CircuitBreakerService circuitBreaker = Mockito.mock(CircuitBreakerService.class);
        BranchDnsProvider provider = new BranchDnsProvider(circuitBreaker,
                clientHandling(response(200, null, new byte[]{1})), DNSFormat.PATH_MESSAGE);

        Assertions.assertThat(provider.lookupAndCache("example.com")).isEqualTo(LookupVerdict.FAILED);
        Mockito.verify(circuitBreaker, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(),
                ArgumentMatchers.anyLong());
    }

    @Test
    void rejectsANullBodyReturnedByTheEntityUtility() throws IOException {
        CircuitBreakerService circuitBreaker = Mockito.mock(CircuitBreakerService.class);
        HttpEntity entity = new ByteArrayEntity(new byte[]{1}, ContentType.parse("application/dns-message"));
        BranchDnsProvider provider = new BranchDnsProvider(circuitBreaker,
                clientHandling(response(200, "application/dns-message", entity)), DNSFormat.PATH_MESSAGE);

        try (MockedStatic<EntityUtils> entityUtils = Mockito.mockStatic(EntityUtils.class)) {
            entityUtils.when(() -> EntityUtils.toByteArray(entity, 64 << 10)).thenReturn(null);

            Assertions.assertThat(provider.lookupAndCache("example.com")).isEqualTo(LookupVerdict.FAILED);
        }

        Mockito.verify(circuitBreaker, Mockito.never()).recordSuccess(ArgumentMatchers.anyString(),
                ArgumentMatchers.anyLong());
    }

    @Test
    void handlesFailuresClosingSharedDnsClients() throws Exception {
        Method close = AbstractDNSProvider.class.getDeclaredMethod("closeHttpClient", String.class, Closeable.class);
        close.setAccessible(true);
        close.invoke(null, "test", (Closeable) () -> {
            throw new IOException("closed");
        });
    }

    @SuppressWarnings("unchecked")
    private static CloseableHttpClient clientHandling(org.apache.hc.core5.http.ClassicHttpResponse response)
            throws IOException {
        CloseableHttpClient client = Mockito.mock(CloseableHttpClient.class);
        Mockito.when(client.execute(ArgumentMatchers.any(ClassicHttpRequest.class),
                        ArgumentMatchers.<HttpClientResponseHandler<Object>>any()))
                .thenAnswer(invocation -> invocation.<HttpClientResponseHandler<Object>>getArgument(1)
                        .handleResponse(response));
        return client;
    }

    private static BasicClassicHttpResponse response(int status, String contentType, byte[] body) {
        BasicClassicHttpResponse response = new BasicClassicHttpResponse(status);
        if (contentType != null) {
            response.addHeader("Content-Type", contentType);
        }
        response.setEntity(new ByteArrayEntity(body, contentType == null ? null : ContentType.parse(contentType)));
        return response;
    }

    private static BasicClassicHttpResponse response(int status, String contentType, HttpEntity body) {
        BasicClassicHttpResponse response = new BasicClassicHttpResponse(status);
        response.addHeader("Content-Type", contentType);
        response.setEntity(body);
        return response;
    }
}
