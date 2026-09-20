package net.foulest.ospreyproxy.handlers;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.store.ScanRecord;
import net.foulest.ospreyproxy.store.ScanStore;
import net.foulest.ospreyproxy.util.check.CheckRequest;
import net.foulest.ospreyproxy.util.check.IndexedVerdict;
import net.foulest.ospreyproxy.util.check.PreparedUrl;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.FutureTask;

import static org.mockito.Mockito.*;

class CheckHandlerTest {

    @Test
    void prepareNormalizesPublicUrlsAndRejectsUnsafeInputs() {
        PreparedUrl prepared = CheckHandler.prepare("HTTP://WWW.Example.COM/path///?ignored=yes#fragment");
        Assertions.assertThat(prepared.host()).isEqualTo("example.com");
        Assertions.assertThat(prepared.bareHost()).isEqualTo("example.com");
        Assertions.assertThat(prepared.canonicalUrl()).isEqualTo("https://example.com/path");
        Assertions.assertThat(prepared.hasRegistrableDomain()).isTrue();
        Assertions.assertThat(CheckHandler.prepare("example.com")).isNotNull();
        Assertions.assertThat(CheckHandler.prepare(null)).isNull();
        Assertions.assertThat(CheckHandler.prepare("  ")).isNull();
        Assertions.assertThat(CheckHandler.prepare("ftp://example.com")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http://localhost")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http://127.0.0.1")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http://[::1]")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http:///missing")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http://a")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http://exa mple.com")).isNull();
        Assertions.assertThat(CheckHandler.prepare("http:")).isNull();
        Assertions.assertThat(CheckHandler.prepare("https://localhost")).isNull();
        Assertions.assertThat(CheckHandler.prepare("x".repeat(8193))).isNull();
        Assertions.assertThat(CheckHandler.prepare("https://example.com.")).isNotNull();
        Assertions.assertThat(CheckHandler.prepare("https://example.com/")).isNotNull();
        CheckHandler.prepare("https://[2001:db8::1]");
        Assertions.assertThat(CheckHandler.prepare("https://[::ffff:8.8.8.8]")).isNotNull();
        CheckHandler.prepare("https://" + "a".repeat(250) + ".com");
    }

    @Test
    void checkRejectsMissingUrlAndExhaustedBurstBudget() {
        CheckHandler handler = handler(null, List.of(), 1);
        HttpServletRequest request = request();

        StatusCodeException missingUrl = Assertions.catchThrowableOfType(
                () -> handler.check(null, request), StatusCodeException.class);
        Assertions.assertThat(missingUrl.getStatus().getStatusCode().value()).isEqualTo(400);

        StatusCodeException limited = Assertions.catchThrowableOfType(
                () -> handler.check(new CheckRequest("example.com", null, false), request), StatusCodeException.class);
        Assertions.assertThat(limited.getStatus().getStatusCode().value()).isEqualTo(429);
    }

    @Test
    void checkStreamsOnlyEnabledProvidersAndConvertsResolverFailureToFailed() throws Exception {
        Provider enabled = mock(Provider.class);
        when(enabled.isEnabled()).thenReturn(true);
        when(enabled.getEndpointName()).thenReturn("enabled");
        when(enabled.getDisplayName()).thenReturn("Enabled");
        Provider disabled = mock(Provider.class);
        when(disabled.isEnabled()).thenReturn(false);

        ProxyHandler proxy = mock(ProxyHandler.class);
        when(proxy.resolveForCheck(eq(enabled), any())).thenThrow(new IllegalStateException("upstream unavailable"));
        CheckHandler handler = handler(null, List.of(enabled, disabled), 5, proxy);

        ResponseEntity<StreamingResponseBody> response =
                handler.check(new CheckRequest("example.com", null, false), request());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        response.getBody().writeTo(output);

        String lines = output.toString(StandardCharsets.UTF_8);
        Assertions.assertThat(lines)
                .contains("\"count\":1", "\"provider\":\"enabled\"", "\"result\":\"failed\"", "\"flagged\":0");
        verify(proxy).resolveForCheck(eq(enabled), any());
        verify(disabled, never()).getEndpointName();
    }

    @Test
    void checkReplaysFreshStoredScanUnlessForced() throws Exception {
        ScanStore store = mock(ScanStore.class);
        ScanRecord record = record(System.currentTimeMillis(), Map.of("cached", List.of("malicious")));
        when(store.get("https://example.com")).thenReturn(record);
        CheckHandler handler = handler(store, List.of(), 5);

        ResponseEntity<StreamingResponseBody> response =
                handler.check(new CheckRequest("example.com", null, false), request());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        response.getBody().writeTo(output);

        Assertions.assertThat(output.toString(StandardCharsets.UTF_8))
                .contains("\"provider\":\"cached\"", "\"cached\":true");
        handler.check(new CheckRequest("example.com", null, true), request());
        verify(store).get("https://example.com");
    }

    @Test
    void checkStreamsThreatsAndRepresentsEmptyStoredProviderValuesAsFailures() throws Exception {
        Provider allowed = provider("allowed");
        Provider malicious = provider("malicious");
        Provider limited = provider("limited");
        ProxyHandler proxy = mock(ProxyHandler.class);
        when(proxy.resolveForCheck(allowed, CheckHandler.prepare("example.com")))
                .thenReturn(net.foulest.ospreyproxy.result.LookupVerdict.ALLOWED);
        when(proxy.resolveForCheck(malicious, CheckHandler.prepare("example.com")))
                .thenReturn(net.foulest.ospreyproxy.result.LookupVerdict.of(LookupResult.MALICIOUS));
        when(proxy.resolveForCheck(limited, CheckHandler.prepare("example.com")))
                .thenReturn(net.foulest.ospreyproxy.result.LookupVerdict.RATE_LIMITED);

        CheckHandler live = handler(null, List.of(allowed, malicious, limited), 10, proxy);
        ByteArrayOutputStream liveOutput = new ByteArrayOutputStream();
        live.check(new CheckRequest("example.com", null, false), request()).getBody().writeTo(liveOutput);
        Assertions.assertThat(liveOutput.toString(StandardCharsets.UTF_8))
                .contains("\"provider\":\"malicious\"", "\"flagged\":1");

        ScanStore store = mock(ScanStore.class);
        when(store.get("https://example.com")).thenReturn(record(System.currentTimeMillis(), Map.of("cached", List.of())));
        CheckHandler cached = handler(store, List.of(), 10);
        ByteArrayOutputStream cachedOutput = new ByteArrayOutputStream();
        cached.check(new CheckRequest("example.com", null, false), request()).getBody().writeTo(cachedOutput);
        Assertions.assertThat(cachedOutput.toString(StandardCharsets.UTF_8))
                .contains("\"provider\":\"cached\"", "\"result\":\"failed\"");
    }

    @Test
    void checkFailsClosedWhenTurnstileIsEnabledWithoutASecret() {
        ObjectProvider<ScanStore> storeProvider = mock(ObjectProvider.class);
        when(storeProvider.getIfAvailable()).thenReturn(null);
        CheckHandler handler = new CheckHandler(mock(ProxyHandler.class), List.of(), storeProvider, 60,
                true, "", "http://unused", 1, 10, 3600, 100, 3600, 1);

        StatusCodeException exception = Assertions.catchThrowableOfType(
                () -> handler.check(new CheckRequest("example.com", "token", false), request()),
                StatusCodeException.class);
        Assertions.assertThat(exception.getStatus().getStatusCode().value()).isEqualTo(403);
    }

    @Test
    void checkAppliesTheSustainedRateLimitAfterTheBurstLimitPasses() {
        ObjectProvider<ScanStore> storeProvider = storeProvider(null);
        CheckHandler handler = new CheckHandler(mock(ProxyHandler.class), List.of(), storeProvider, 60,
                false, "", "http://unused", 1, 2, 3600, 1, 3600, 1, mock(HttpClient.class));
        HttpServletRequest request = request();
        handler.check(new CheckRequest("example.com", null, false), request);

        StatusCodeException exception = Assertions.catchThrowableOfType(
                () -> handler.check(new CheckRequest("example.com", null, false), request), StatusCodeException.class);
        Assertions.assertThat(exception.getStatus().getStatusCode().value()).isEqualTo(429);
    }

    @Test
    void turnstileClientHandlesRemoteIpStatusAndTransportOutcomes() throws Exception {
        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn("{\"success\":true}");
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);
        CheckHandler handler = handler(null, List.of(), 5, mock(ProxyHandler.class), true, "secret", client, 1);
        HttpServletRequest request = request();
        when(request.getHeader("X-Real-IP")).thenReturn(" 2001:db8::1 ");

        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(true);
        when(request.getHeader("X-Real-IP")).thenReturn("not-an-ip");
        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(true);
        when(request.getHeader("X-Real-IP")).thenReturn("x".repeat(46));
        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(true);

        when(response.statusCode()).thenReturn(400);
        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(false);
        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, null, request)).isEqualTo(false);
        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, " ", request)).isEqualTo(false);
        Assertions.assertThat(invokeInstance(handler, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, "x".repeat(2049), request)).isEqualTo(false);

        HttpClient interruptedClient = mock(HttpClient.class);
        when(interruptedClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("interrupted"));
        CheckHandler interrupted = handler(null, List.of(), 5, mock(ProxyHandler.class),
                true, "secret", interruptedClient, 1);
        try {
            Assertions.assertThat(invokeInstance(interrupted, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request())).isEqualTo(false);
            Assertions.assertThat(Thread.interrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }

        HttpClient failedClient = mock(HttpClient.class);
        when(failedClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("unavailable"));
        CheckHandler failed = handler(null, List.of(), 5, mock(ProxyHandler.class), true, "secret", failedClient, 1);
        Assertions.assertThat(invokeInstance(failed, "verifyTurnstile",
                new Class[]{String.class, HttpServletRequest.class}, "captcha", request())).isEqualTo(false);
    }

    @Test
    void streamingHandlesDeadlineFailedFuturesAndPersistenceOutcomes() throws Exception {
        Provider deadlineProvider = provider("deadline");
        ProxyHandler slowProxy = mock(ProxyHandler.class);
        when(slowProxy.resolveForCheck(eq(deadlineProvider), any())).thenAnswer(ignored -> {
            Thread.sleep(1_100L);
            return net.foulest.ospreyproxy.result.LookupVerdict.ALLOWED;
        });
        CheckHandler deadline = handler(null, List.of(deadlineProvider), 5, slowProxy, false, "", mock(HttpClient.class), 1);
        deadline.check(new CheckRequest("example.com", null, false), request()).getBody().writeTo(new ByteArrayOutputStream());

        Provider failingProvider = provider("failed-future");
        when(failingProvider.getDisplayName()).thenThrow(new IllegalStateException("display unavailable"));
        ProxyHandler failingProxy = mock(ProxyHandler.class);
        when(failingProxy.resolveForCheck(eq(failingProvider), any())).thenThrow(new IllegalStateException("upstream unavailable"));
        CheckHandler failedFuture = handler(null, List.of(failingProvider), 5, failingProxy, false, "", mock(HttpClient.class), 1);
        failedFuture.check(new CheckRequest("example.com", null, false), request()).getBody().writeTo(new ByteArrayOutputStream());

        ScanStore store = mock(ScanStore.class);
        Provider allowedProvider = provider("allowed");
        ProxyHandler allowedProxy = mock(ProxyHandler.class);
        when(allowedProxy.resolveForCheck(eq(allowedProvider), any()))
                .thenReturn(net.foulest.ospreyproxy.result.LookupVerdict.ALLOWED);
        CheckHandler persistent = handler(store, List.of(allowedProvider), 5, allowedProxy, false, "", mock(HttpClient.class), 1);
        persistent.check(new CheckRequest("example.com", null, true), request()).getBody().writeTo(new ByteArrayOutputStream());
        verify(store).upsert(any(ScanRecord.class));

        CheckHandler degraded = handler(store, List.of(), 5, mock(ProxyHandler.class), false, "", mock(HttpClient.class), 0);
        degraded.check(new CheckRequest("example.com", null, true), request()).getBody().writeTo(new ByteArrayOutputStream());
        verify(store, times(1)).upsert(any(ScanRecord.class));
    }

    @Test
    void streamingWithAnImmediateDeadlineMarksProvidersAsFailed() throws Exception {
        Provider provider = provider("immediate");
        CheckHandler handler = handler(null, List.of(provider), 5, mock(ProxyHandler.class),
                false, "", mock(HttpClient.class), 0);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        handler.check(new CheckRequest("example.com", null, false), request()).getBody().writeTo(output);

        Assertions.assertThat(output.toString(StandardCharsets.UTF_8))
                .contains("\"provider\":\"immediate\"", "\"result\":\"failed\"");
    }

    @Test
    void staleAndMissingStoredRecordsFallThroughToLiveScanning() {
        ScanStore store = mock(ScanStore.class);
        when(store.get("https://example.com"))
                .thenReturn(record(System.currentTimeMillis() - 61_000L, Map.of("stale", List.of("allowed"))),
                        (ScanRecord) null);
        CheckHandler handler = handler(store, List.of(), 5);
        handler.check(new CheckRequest("example.com", null, false), request());
        handler.check(new CheckRequest("example.com", null, false), request());
        verify(store, times(2)).get("https://example.com");
    }

    @Test
    void privateHelpersHandleInvalidIpCharactersAndFailedFutures() throws Exception {
        Assertions.assertThat(invokeStatic("isIpLiteral", new Class[]{String.class}, "")).isEqualTo(false);
        Assertions.assertThat(invokeStatic("isIpLiteral", new Class[]{String.class}, "2001:db8:A.1")).isEqualTo(true);
        Assertions.assertThat(invokeStatic("isIpLiteral", new Class[]{String.class}, "1.2.3.x")).isEqualTo(false);
        Assertions.assertThat(invokeStatic("isFlagged",
                new Class[]{net.foulest.ospreyproxy.result.LookupVerdict.class},
                net.foulest.ospreyproxy.result.LookupVerdict.ALLOWED)).isEqualTo(false);
        Assertions.assertThat(invokeStatic("isFlagged",
                new Class[]{net.foulest.ospreyproxy.result.LookupVerdict.class},
                net.foulest.ospreyproxy.result.LookupVerdict.of(LookupResult.PHISHING))).isEqualTo(true);

        FutureTask<IndexedVerdict> failed = new FutureTask<>(() -> {
            throw new IllegalStateException("failed");
        });
        failed.run();
        Assertions.assertThat(invokeStatic("safeGet", new Class[]{java.util.concurrent.Future.class}, failed)).isNull();
    }

    @Test
    void containsStreamingAndPersistenceFailures() throws Exception {
        Method write = CheckHandler.class.getDeclaredMethod("writeLine", OutputStream.class, Map.class);
        write.setAccessible(true);
        write.invoke(null, new OutputStream() {
            @Override
            public void write(int value) throws IOException {
                throw new IOException("closed");
            }
        }, Map.of("type", "result"));

        ScanStore store = mock(ScanStore.class);
        doThrow(new IllegalStateException("offline")).when(store).upsert(any());
        CheckHandler handler = failureHandler(store);
        Method persist = CheckHandler.class.getDeclaredMethod("persist", PreparedUrl.class, Map.class);
        persist.setAccessible(true);
        persist.invoke(handler, new PreparedUrl("example.com", "example.com", "https://example.com", true),
                Map.of("provider", net.foulest.ospreyproxy.result.LookupVerdict.ALLOWED));

        Method safeGet = CheckHandler.class.getDeclaredMethod("safeGet", java.util.concurrent.Future.class);
        safeGet.setAccessible(true);
        FutureTask<Object> task = new FutureTask<>(() -> null);
        Thread.currentThread().interrupt();
        try {
            Assertions.assertThat(safeGet.invoke(null, task)).isNull();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void interruptedScansRestoreTheFlagAndReportStragglersAsFailed() throws Exception {
        ProxyHandler proxy = mock(ProxyHandler.class);
        when(proxy.resolveForCheck(any(), any()))
                .thenReturn(net.foulest.ospreyproxy.result.LookupVerdict.ALLOWED);

        Provider provider = mock(Provider.class);
        when(provider.getEndpointName()).thenReturn("provider");
        when(provider.getDisplayName()).thenReturn("Provider");

        CheckHandler handler = failureHandler(mock(ScanStore.class), proxy);
        Method stream = CheckHandler.class.getDeclaredMethod("streamResults",
                OutputStream.class, java.util.List.class, PreparedUrl.class);
        stream.setAccessible(true);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PreparedUrl prepared = new PreparedUrl("example.com", "example.com", "https://example.com", true);

        boolean interrupted;
        Thread.currentThread().interrupt();
        try {
            stream.invoke(handler, out, java.util.List.of(provider), prepared);
        } finally {
            interrupted = Thread.interrupted();
        }

        Assertions.assertThat(interrupted).isTrue();
        String body = out.toString(StandardCharsets.UTF_8);
        Assertions.assertThat(body).contains("\"type\":\"meta\"")
                .contains("\"provider\":\"provider\"")
                .contains("\"type\":\"done\"");
    }

    @Test
    void prepareRejectsHostsThatCannotBeIdnEncoded() {
        Assertions.assertThat(CheckHandler.prepare("https://" + "a".repeat(64) + ".example")).isNull();
        Assertions.assertThat(CheckHandler.prepare("https://example.com")).isNotNull();
    }

    @SuppressWarnings("unchecked")
    private static CheckHandler failureHandler(ScanStore store) {
        return failureHandler(store, mock(ProxyHandler.class));
    }

    @SuppressWarnings("unchecked")
    private static CheckHandler failureHandler(ScanStore store, ProxyHandler proxyHandler) {
        ObjectProvider<ScanStore> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(store);
        return new CheckHandler(proxyHandler, java.util.List.of(), provider,
                60, false, "", "http://unused", 1, 1, 60, 1, 60, 1);
    }

    private static CheckHandler handler(ScanStore store, List<Provider> providers, long capacity) {
        return handler(store, providers, capacity, mock(ProxyHandler.class));
    }

    @SuppressWarnings("unchecked")
    private static CheckHandler handler(ScanStore store, List<Provider> providers, long capacity, ProxyHandler proxy) {
        return handler(store, providers, capacity, proxy, false, "", mock(HttpClient.class), 1);
    }

    private static CheckHandler handler(ScanStore store, List<Provider> providers, long capacity, ProxyHandler proxy,
                                        boolean turnstileEnabled, String turnstileSecret, HttpClient client,
                                        long deadlineSeconds) {
        ObjectProvider<ScanStore> storeProvider = storeProvider(store);
        return new CheckHandler(proxy, providers, storeProvider, 60, turnstileEnabled, turnstileSecret, "http://unused", 1,
                capacity, 3600, 100, 3600, deadlineSeconds, client);
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<ScanStore> storeProvider(ScanStore store) {
        ObjectProvider<ScanStore> storeProvider = mock(ObjectProvider.class);
        when(storeProvider.getIfAvailable()).thenReturn(store);
        return storeProvider;
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("8.8.8.8");
        return request;
    }

    private static ScanRecord record(long scannedAt, Map<String, List<String>> results) {
        return new ScanRecord("https://example.com", "example.com", "example.com", "malicious", results,
                1, results.size(), scannedAt, scannedAt, 1, true, null);
    }

    private static Provider provider(String endpoint) {
        Provider provider = mock(Provider.class);
        when(provider.isEnabled()).thenReturn(true);
        when(provider.getEndpointName()).thenReturn(endpoint);
        when(provider.getDisplayName()).thenReturn(endpoint);
        return provider;
    }

    private static Object invokeStatic(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = CheckHandler.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    private static Object invokeInstance(Object target, String name, Class<?>[] types, Object... args) throws Exception {
        Method method = target.getClass().getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(target, args);
    }
}
