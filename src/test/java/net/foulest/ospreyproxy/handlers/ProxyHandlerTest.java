package net.foulest.ospreyproxy.handlers;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.AbstractDNSProvider;
import net.foulest.ospreyproxy.providers.AbstractProvider;
import net.foulest.ospreyproxy.providers.Provider;
import net.foulest.ospreyproxy.result.LookupResult;
import net.foulest.ospreyproxy.result.LookupVerdict;
import net.foulest.ospreyproxy.services.CircuitBreakerService;
import net.foulest.ospreyproxy.services.MetricsService;
import net.foulest.ospreyproxy.tenant.TenantService;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.NetworkUtil;
import net.foulest.ospreyproxy.util.RateLimitUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import net.foulest.ospreyproxy.util.check.PreparedUrl;
import net.foulest.ospreyproxy.util.list.Descriptor;
import net.foulest.ospreyproxy.util.list.LocalListUtil;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ProxyHandlerTest {

    private static final byte[] BODY = "{}".getBytes(StandardCharsets.UTF_8);
    private static final String PROVIDER_NAME = "Provider";
    private static final String ENDPOINT = "provider";
    private static final String HOST = "www.example.com";
    private static final String BARE_HOST = "example.com";
    private static final URI URI_VALUE = URI.create("https://" + HOST + "/path");

    @Test
    void springConstructorFallsBackToTheSharedHttpClient() throws Exception {
        ProxyHandler handler = new ProxyHandler(List.of(),
                mock(MetricsService.class), mock(CircuitBreakerService.class));

        Field instanceClient = ProxyHandler.class.getDeclaredField("httpClient");
        instanceClient.setAccessible(true);
        Field sharedClient = ProxyHandler.class.getDeclaredField("HTTP_CLIENT");
        sharedClient.setAccessible(true);

        Assertions.assertThat(instanceClient.get(handler)).isSameAs(sharedClient.get(null));
    }

    @Test
    void resultResponseFallsBackToBadGatewayWhenSerializationFails() throws Exception {
        Method resultResponse = ProxyHandler.class.getDeclaredMethod("resultResponse",
                LookupVerdict.class, String.class);
        resultResponse.setAccessible(true);

        LookupVerdict broken = mock(LookupVerdict.class);
        when(broken.primary()).thenThrow(new IllegalStateException("unreadable verdict"));

        Assertions.assertThat(resultResponse.invoke(null, broken, "Provider")).isSameAs(ErrorUtil.RESP_502);
    }

    @Test
    void handleProviderDispatchesUnknownDisabledAndEnabledProviders() {
        MetricsService metrics = mock(MetricsService.class);
        Provider disabled = baseProvider(mock(Provider.class));
        when(disabled.isEnabled()).thenReturn(false);
        ProxyHandler disabledHandler = new ProxyHandler(List.of(disabled), metrics, mock(CircuitBreakerService.class),
                mock(CloseableHttpClient.class));

        Assertions.assertThat(disabledHandler.handleProvider("missing", BODY, request()).getStatusCode().value()).isEqualTo(404);
        Assertions.assertThat(disabledHandler.handleProvider(ENDPOINT, BODY, request()).getStatusCode().value()).isEqualTo(503);

        verify(metrics).recordBlocked("unknown", 404, TenantService.ANONYMOUS);
        verify(metrics).recordBlocked(PROVIDER_NAME, 503, TenantService.ANONYMOUS);
    }

    @Test
    void proxyRequestUsesBothRateTenantModesAndRecordsValidationFailures() throws Exception {
        Provider provider = baseProvider(mock(Provider.class));
        MetricsService metrics = mock(MetricsService.class);
        CircuitBreakerService circuit = mock(CircuitBreakerService.class);
        when(circuit.isOpen(PROVIDER_NAME)).thenReturn(true);
        ProxyHandler handler = handler(provider, metrics, circuit, mock(CloseableHttpClient.class));
        HttpServletRequest request = request();

        try (MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class);
             MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class)) {
            validInput(requests, request, provider, null);
            Assertions.assertThat(proxy(handler, request, provider, TenantService.ANONYMOUS).getStatusCode().value())
                    .isEqualTo(429);

            validInput(requests, request, provider, "tenant-a");
            requests.when(() -> RequestUtil.validateIP(request, provider, PROVIDER_NAME, "tenant-a"))
                    .thenThrow(new StatusCodeException(ErrorUtil.RESP_422));
            Assertions.assertThat(proxy(handler, request, provider, "tenant-a").getStatusCode().value()).isEqualTo(422);
        }

        verify(metrics).recordBlocked(PROVIDER_NAME, 422, "tenant-a");
    }

    @Test
    void proxyRequestHandlesBareHostsAndAllLookupKeyForms() throws Exception {
        HttpServletRequest request = request();

        try (MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class);
             MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class);
             MockedStatic<NetworkUtil> network = mockStatic(NetworkUtil.class)) {
            network.when(() -> NetworkUtil.isPrivateHost(HOST)).thenReturn(false);

            Provider barePublicSuffix = baseProvider(mock(Provider.class));
            when(barePublicSuffix.isStripToBareHost()).thenReturn(true);
            ProxyHandler suffixHandler = handler(barePublicSuffix, mock(MetricsService.class),
                    mock(CircuitBreakerService.class), mock(CloseableHttpClient.class));
            validInput(requests, request, barePublicSuffix, "tenant");
            bareHostInput(requests, false);
            Assertions.assertThat(proxy(suffixHandler, request, barePublicSuffix, "tenant").getBody())
                    .contains("\"result\":\"allowed\"");

            AbstractProvider cachedBarePublicSuffix = baseProvider(mock(AbstractProvider.class));
            when(cachedBarePublicSuffix.isStripToBareHost()).thenReturn(true);
            ProxyHandler cachedSuffixHandler = handler(cachedBarePublicSuffix, mock(MetricsService.class),
                    mock(CircuitBreakerService.class), mock(CloseableHttpClient.class));
            validInput(requests, request, cachedBarePublicSuffix, "tenant");
            bareHostInput(requests, false);
            Assertions.assertThat(proxy(cachedSuffixHandler, request, cachedBarePublicSuffix, "tenant").getStatusCode().value())
                    .isEqualTo(200);
            verify(cachedBarePublicSuffix).putCachedResult(BARE_HOST, LookupVerdict.ALLOWED);

            Provider bareHostProvider = baseProvider(mock(Provider.class));
            when(bareHostProvider.isStripToBareHost()).thenReturn(true);
            CircuitBreakerService bareCircuit = openCircuit();
            ProxyHandler bareHandler = handler(bareHostProvider, mock(MetricsService.class), bareCircuit,
                    mock(CloseableHttpClient.class));
            validInput(requests, request, bareHostProvider, "tenant");
            bareHostInput(requests, true);
            Assertions.assertThat(proxy(bareHandler, request, bareHostProvider, "tenant").getStatusCode().value())
                    .isEqualTo(429);

            Provider hostProvider = baseProvider(mock(Provider.class));
            when(hostProvider.isStripToHost()).thenReturn(true);
            ProxyHandler hostHandler = handler(hostProvider, mock(MetricsService.class), openCircuit(),
                    mock(CloseableHttpClient.class));
            validInput(requests, request, hostProvider, "tenant");
            Assertions.assertThat(proxy(hostHandler, request, hostProvider, "tenant").getStatusCode().value())
                    .isEqualTo(429);

            Provider urlProvider = baseProvider(mock(Provider.class));
            ProxyHandler urlHandler = handler(urlProvider, mock(MetricsService.class), openCircuit(),
                    mock(CloseableHttpClient.class));
            validInput(requests, request, urlProvider, "tenant");
            Assertions.assertThat(proxy(urlHandler, request, urlProvider, "tenant").getStatusCode().value())
                    .isEqualTo(429);
            requests.verify(() -> RequestUtil.reconstructURI(
                    URI_VALUE, HOST, "https", urlProvider, PROVIDER_NAME, "hashed-ip"), atLeast(2));
        }
    }

    @Test
    void proxyRequestUsesCachePrivateHostDnsAndLocalListRoutes() throws Exception {
        HttpServletRequest request = request();

        try (MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class);
             MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class);
             MockedStatic<NetworkUtil> network = mockStatic(NetworkUtil.class);
             MockedStatic<RateLimitUtil> limits = mockStatic(RateLimitUtil.class)) {
            network.when(() -> NetworkUtil.isPrivateHost(HOST)).thenReturn(false);

            AbstractProvider cached = baseProvider(mock(AbstractProvider.class));
            when(cached.getCachedResult(URI_VALUE.toString())).thenReturn(LookupVerdict.ALLOWED);
            MetricsService cachedMetrics = mock(MetricsService.class);
            ProxyHandler cachedHandler = handler(cached, cachedMetrics, mock(CircuitBreakerService.class),
                    mock(CloseableHttpClient.class));
            validInput(requests, request, cached, "tenant");
            Assertions.assertThat(proxy(cachedHandler, request, cached, "tenant").getBody()).contains("\"allowed\"");
            verify(cachedMetrics).recordCacheHit();

            AbstractProvider cacheMiss = baseProvider(mock(AbstractProvider.class));
            CircuitBreakerService missCircuit = openCircuit();
            ProxyHandler missHandler = handler(cacheMiss, mock(MetricsService.class), missCircuit,
                    mock(CloseableHttpClient.class));
            validInput(requests, request, cacheMiss, "tenant");
            Assertions.assertThat(proxy(missHandler, request, cacheMiss, "tenant").getStatusCode().value()).isEqualTo(429);

            Provider privateHost = baseProvider(mock(Provider.class));
            ProxyHandler privateHandler = handler(privateHost, mock(MetricsService.class), mock(CircuitBreakerService.class),
                    mock(CloseableHttpClient.class));
            validInput(requests, request, privateHost, "tenant");
            network.when(() -> NetworkUtil.isPrivateHost(HOST)).thenReturn(true);
            Assertions.assertThat(proxy(privateHandler, request, privateHost, "tenant").getStatusCode().value()).isEqualTo(400);
            limits.verify(() -> RateLimitUtil.rejectInvalidRequest(privateHost, "hashed-ip", PROVIDER_NAME, ""));
            network.when(() -> NetworkUtil.isPrivateHost(HOST)).thenReturn(false);

            AbstractDNSProvider dns = baseProvider(mock(AbstractDNSProvider.class));
            when(dns.lookupAndCache(HOST)).thenReturn(LookupVerdict.RATE_LIMITED, LookupVerdict.of(LookupResult.MALICIOUS),
                    LookupVerdict.of(LookupResult.PHISHING), LookupVerdict.ALLOWED);
            ProxyHandler dnsHandler = handler(dns, mock(MetricsService.class), mock(CircuitBreakerService.class),
                    mock(CloseableHttpClient.class));
            validInput(requests, request, dns, "tenant");
            Assertions.assertThat(proxy(dnsHandler, request, dns, "tenant").getStatusCode().value()).isEqualTo(429);
            Assertions.assertThat(proxy(dnsHandler, request, dns, "tenant").getStatusCode().value()).isEqualTo(200);
            Assertions.assertThat(proxy(dnsHandler, request, dns, "tenant").getStatusCode().value()).isEqualTo(200);
            Assertions.assertThat(proxy(dnsHandler, request, dns, "tenant").getStatusCode().value()).isEqualTo(200);

            Provider listProvider = baseProvider(mock(Provider.class));
            lists.when(() -> LocalListUtil.findByEndpointName(ENDPOINT)).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.lookup(Descriptor.ACOMICS, URI_VALUE.toString()))
                    .thenReturn(LookupResult.MALICIOUS, LookupResult.PHISHING, LookupResult.ALLOWED);
            ProxyHandler listHandler = handler(listProvider, mock(MetricsService.class), mock(CircuitBreakerService.class),
                    mock(CloseableHttpClient.class));
            validInput(requests, request, listProvider, "tenant");
            Assertions.assertThat(proxy(listHandler, request, listProvider, "tenant").getStatusCode().value()).isEqualTo(200);
            Assertions.assertThat(proxy(listHandler, request, listProvider, "tenant").getStatusCode().value()).isEqualTo(200);
            Assertions.assertThat(proxy(listHandler, request, listProvider, "tenant").getStatusCode().value()).isEqualTo(200);
        }
    }

    @Test
    void executeUpstreamBuildsRequestWithBodiesAndHeadersAndCachesResults() throws Exception {
        AbstractProvider provider = baseProvider(mock(AbstractProvider.class));
        when(provider.getMethod()).thenReturn(org.apache.hc.core5.http.Method.POST);
        when(provider.buildBody("https://target.example")).thenReturn(Map.of("url", "https://target.example"));
        when(provider.getHeaders()).thenReturn(Map.of("X-Key", "secret"));
        when(provider.interpretAll(any(byte[].class), eq("https://target.example"))).thenReturn(LookupVerdict.ALLOWED);
        CloseableHttpClient client = mock(CloseableHttpClient.class);
        AtomicReference<ClassicHttpRequest> captured = new AtomicReference<>();
        respond(client, 200, entity("ok"), captured);
        CircuitBreakerService circuit = mock(CircuitBreakerService.class);
        ProxyHandler handler = handler(provider, mock(MetricsService.class), circuit, client);

        ResponseEntity<String> response = upstream(handler, provider, "https://target.example");

        Assertions.assertThat(response.getStatusCode().value()).isEqualTo(200);
        Assertions.assertThat(response.getBody()).isEqualTo("{\"result\":\"allowed\",\"results\":[\"allowed\"]}");
        Assertions.assertThat(captured.get().getMethod()).isEqualTo("POST");
        Assertions.assertThat(captured.get().getFirstHeader("X-Key").getValue()).isEqualTo("secret");
        Assertions.assertThat(captured.get().getEntity()).isNotNull();
        verify(circuit).recordSuccess(eq(PROVIDER_NAME), anyLong());
        verify(provider).putCachedResult("https://target.example", LookupVerdict.ALLOWED);
    }

    @Test
    void executeUpstreamMapsEveryResponseStatusAndPayloadBoundary() throws Exception {
        Assertions.assertThat(upstreamStatus(400, entity("error"), false)).isEqualTo(400);
        Assertions.assertThat(upstreamStatus(401, entity("error"), false)).isEqualTo(502);
        Assertions.assertThat(upstreamStatus(498, entity("error"), false)).isEqualTo(502);
        Assertions.assertThat(upstreamStatus(404, entity("error"), false)).isEqualTo(404);
        Assertions.assertThat(upstreamStatus(415, entity("error"), false)).isEqualTo(415);
        Assertions.assertThat(upstreamStatus(422, entity("error"), false)).isEqualTo(422);
        Assertions.assertThat(upstreamStatus(429, entity("error"), false)).isEqualTo(429);
        Assertions.assertThat(upstreamStatus(418, entity("error"), false)).isEqualTo(502);
        Assertions.assertThat(upstreamStatus(500, entity("error"), false)).isEqualTo(502);
        Assertions.assertThat(upstreamStatus(200, entity(new byte[0]), false)).isEqualTo(502);
        Assertions.assertThat(upstreamStatus(200, entity("ok"), false)).isEqualTo(200);
        Assertions.assertThat(upstreamStatus(404, entity("not found"), true)).isEqualTo(200);
        Assertions.assertThat(upstreamStatus(200, entity(new byte[1_048_577]), false)).isEqualTo(502);
    }

    @Test
    void executeUpstreamLogsAllVerdictSeveritiesAndHandlesBodySerializationFailure() throws Exception {
        for (LookupVerdict verdict : List.of(LookupVerdict.of(LookupResult.MALICIOUS),
                LookupVerdict.of(LookupResult.PHISHING), LookupVerdict.ALLOWED)) {
            Provider provider = baseProvider(mock(Provider.class));
            when(provider.interpretAll(any(byte[].class), anyString())).thenReturn(verdict);
            CloseableHttpClient client = mock(CloseableHttpClient.class);
            respond(client, 200, entity("ok"), null);
            Assertions.assertThat(upstream(handler(provider, mock(MetricsService.class), mock(CircuitBreakerService.class), client),
                    provider, "target").getStatusCode().value()).isEqualTo(200);
        }

        Provider unserializableBody = baseProvider(mock(Provider.class));
        Map<String, Object> circular = new java.util.HashMap<>();
        circular.put("self", circular);
        when(unserializableBody.buildBody("target")).thenReturn(circular);
        Assertions.assertThat(upstream(handler(unserializableBody, mock(MetricsService.class),
                mock(CircuitBreakerService.class), mock(CloseableHttpClient.class)), unserializableBody, "target")
                .getStatusCode().value()).isEqualTo(502);
    }

    @Test
    void executeUpstreamHandlesResponseReadAndTransportFailures() throws Exception {
        Provider provider = baseProvider(mock(Provider.class));
        CloseableHttpClient readFailureClient = mock(CloseableHttpClient.class);
        HttpEntity unreadable = mock(HttpEntity.class);
        when(unreadable.getContent()).thenThrow(new IOException("read failed"));
        respond(readFailureClient, 200, unreadable, null);
        Assertions.assertThat(upstream(handler(provider, mock(MetricsService.class), mock(CircuitBreakerService.class),
                readFailureClient), provider, "target").getStatusCode().value()).isEqualTo(502);

        assertTransportStatus(new SocketTimeoutException("timeout"), 504);
        assertTransportStatus(new ConnectionRequestTimeoutException("leased connection timeout"), 504);
        assertTransportStatus(new NoHttpResponseException("upstream closed"), 504);
        assertTransportStatus(new UnknownHostException("private target"), 502);
        assertTransportStatus(new SocketException("socket closed"), 502);
        assertTransportStatus(new IOException("unexpected I/O"), 502);
    }

    @Test
    void resolveForCheckCoversBareHostCacheDnsListAndUpstreamResponses() {
        MetricsService metrics = mock(MetricsService.class);
        CircuitBreakerService circuit = mock(CircuitBreakerService.class);
        PreparedUrl prepared = new PreparedUrl(HOST, BARE_HOST, URI_VALUE.toString(), true);

        AbstractProvider cached = baseProvider(mock(AbstractProvider.class));
        when(cached.getCachedResult(URI_VALUE.toString())).thenReturn(LookupVerdict.ALLOWED);
        ProxyHandler cachedHandler = handler(cached, metrics, circuit, mock(CloseableHttpClient.class));
        Assertions.assertThat(cachedHandler.resolveForCheck(cached, prepared)).isEqualTo(LookupVerdict.ALLOWED);
        verify(metrics).recordCacheHit();

        AbstractProvider bare = baseProvider(mock(AbstractProvider.class));
        when(bare.isStripToBareHost()).thenReturn(true);
        ProxyHandler bareHandler = handler(bare, mock(MetricsService.class), mock(CircuitBreakerService.class),
                mock(CloseableHttpClient.class));
        Assertions.assertThat(bareHandler.resolveForCheck(bare,
                new PreparedUrl("co.uk", "co.uk", "https://co.uk", false))).isEqualTo(LookupVerdict.ALLOWED);
        verify(bare).putCachedResult("co.uk", LookupVerdict.ALLOWED);

        Provider uncachedBarePublicSuffix = baseProvider(mock(Provider.class));
        when(uncachedBarePublicSuffix.isStripToBareHost()).thenReturn(true);
        ProxyHandler uncachedBareHandler = handler(uncachedBarePublicSuffix, mock(MetricsService.class),
                mock(CircuitBreakerService.class), mock(CloseableHttpClient.class));
        Assertions.assertThat(uncachedBareHandler.resolveForCheck(uncachedBarePublicSuffix,
                new PreparedUrl("co.uk", "co.uk", "https://co.uk", false))).isEqualTo(LookupVerdict.ALLOWED);

        Provider uncachedBareHost = baseProvider(mock(Provider.class));
        when(uncachedBareHost.isStripToBareHost()).thenReturn(true);
        ProxyHandler uncachedBareHostHandler = handler(uncachedBareHost, mock(MetricsService.class), openCircuit(),
                mock(CloseableHttpClient.class));
        Assertions.assertThat(uncachedBareHostHandler.resolveForCheck(uncachedBareHost, prepared))
                .isEqualTo(LookupVerdict.RATE_LIMITED);

        AbstractDNSProvider dns = baseProvider(mock(AbstractDNSProvider.class));
        when(dns.lookupAndCache(HOST)).thenReturn(LookupVerdict.of(LookupResult.PHISHING));
        ProxyHandler dnsHandler = handler(dns, mock(MetricsService.class), mock(CircuitBreakerService.class),
                mock(CloseableHttpClient.class));
        Assertions.assertThat(dnsHandler.resolveForCheck(dns, prepared).primary()).isEqualTo(LookupResult.PHISHING);

        Provider hostKeyed = baseProvider(mock(Provider.class));
        when(hostKeyed.isStripToHost()).thenReturn(true);
        CircuitBreakerService hostCircuit = openCircuit();
        ProxyHandler hostHandler = handler(hostKeyed, mock(MetricsService.class), hostCircuit, mock(CloseableHttpClient.class));
        Assertions.assertThat(hostHandler.resolveForCheck(hostKeyed, prepared)).isEqualTo(LookupVerdict.RATE_LIMITED);

        Provider listProvider = baseProvider(mock(Provider.class));
        try (MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class)) {
            lists.when(() -> LocalListUtil.findByEndpointName(ENDPOINT)).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.lookup(Descriptor.ACOMICS, URI_VALUE.toString())).thenReturn(LookupResult.MALICIOUS);
            ProxyHandler listHandler = handler(listProvider, mock(MetricsService.class), mock(CircuitBreakerService.class),
                    mock(CloseableHttpClient.class));
            Assertions.assertThat(listHandler.resolveForCheck(listProvider, prepared).primary()).isEqualTo(LookupResult.MALICIOUS);
        }
    }

    @Test
    void verdictResponseMappingHandlesEveryBooleanAndResultShape() throws Exception {
        Assertions.assertThat(verdict(ResponseEntity.status(429).body("anything"))).isEqualTo(LookupVerdict.RATE_LIMITED);
        Assertions.assertThat(verdict(ResponseEntity.status(500).body("anything"))).isEqualTo(LookupVerdict.FAILED);
        Assertions.assertThat(verdict(ResponseEntity.ok().body(null))).isEqualTo(LookupVerdict.FAILED);
        Assertions.assertThat(verdict(ResponseEntity.ok(""))).isEqualTo(LookupVerdict.FAILED);
        Assertions.assertThat(verdict(ResponseEntity.ok("{bad"))).isEqualTo(LookupVerdict.FAILED);
        Assertions.assertThat(verdict(ResponseEntity.ok("{\"result\":\"malicious\"}")).primary()).isEqualTo(LookupResult.MALICIOUS);
        Assertions.assertThat(verdict(ResponseEntity.ok("{\"results\":[\"allowed\",\"phishing\",\"unknown\"]}"))
                .values()).containsExactly("phishing", "allowed");
        Assertions.assertThat(verdict(ResponseEntity.ok("{\"results\":[\"unknown\"],\"result\":\"allowed\"}")))
                .isEqualTo(LookupVerdict.ALLOWED);
        Assertions.assertThat(verdict(ResponseEntity.ok("{\"results\":[\"unknown\"]}"))).isEqualTo(LookupVerdict.FAILED);
    }

    @Test
    void destroyClosesTheInjectedClientEvenWhenCloseFails() throws Exception {
        CloseableHttpClient closes = mock(CloseableHttpClient.class);
        handler(baseProvider(mock(Provider.class)), mock(MetricsService.class), mock(CircuitBreakerService.class), closes).destroy();
        verify(closes).close();

        CloseableHttpClient brokenClose = mock(CloseableHttpClient.class);
        doThrow(new IOException("close failed")).when(brokenClose).close();
        handler(baseProvider(mock(Provider.class)), mock(MetricsService.class), mock(CircuitBreakerService.class),
                brokenClose).destroy();
        verify(brokenClose).close();
    }

    private static int upstreamStatus(int status, HttpEntity responseEntity, boolean validNotFound) throws Exception {
        Provider provider = baseProvider(mock(Provider.class));
        when(provider.isNotFoundValidResponse()).thenReturn(validNotFound);
        when(provider.interpretAll(any(byte[].class), anyString())).thenReturn(LookupVerdict.ALLOWED);
        CloseableHttpClient client = mock(CloseableHttpClient.class);
        respond(client, status, responseEntity, null);
        CircuitBreakerService circuit = mock(CircuitBreakerService.class);
        return upstream(handler(provider, mock(MetricsService.class), circuit, client), provider, "target")
                .getStatusCode().value();
    }

    private static void assertTransportStatus(IOException failure, int expectedStatus) throws Exception {
        Provider provider = baseProvider(mock(Provider.class));
        CloseableHttpClient client = mock(CloseableHttpClient.class);
        doThrow(failure).when(client).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));
        CircuitBreakerService circuit = mock(CircuitBreakerService.class);
        ResponseEntity<String> response = upstream(handler(provider, mock(MetricsService.class), circuit, client), provider, "target");
        Assertions.assertThat(response.getStatusCode().value()).isEqualTo(expectedStatus);
        if (expectedStatus == 504) {
            verify(circuit).recordFailure(eq(PROVIDER_NAME), anyLong(), same(failure));
        }
    }

    @SuppressWarnings("unchecked")
    private static void respond(CloseableHttpClient client, int status, HttpEntity responseEntity,
                                AtomicReference<ClassicHttpRequest> captured) throws Exception {
        BasicClassicHttpResponse response = new BasicClassicHttpResponse(status);
        response.setEntity(responseEntity);
        doAnswer(invocation -> {
            if (captured != null) {
                captured.set(invocation.getArgument(0));
            }
            HttpClientResponseHandler<Object> handler = invocation.getArgument(1);
            return handler.handleResponse(response);
        }).when(client).execute(any(ClassicHttpRequest.class), any(HttpClientResponseHandler.class));
    }

    private static HttpEntity entity(String body) {
        return entity(body.getBytes(StandardCharsets.UTF_8));
    }

    private static HttpEntity entity(byte[] body) {
        return new ByteArrayEntity(body, ContentType.APPLICATION_JSON);
    }

    private static void validInput(MockedStatic<RequestUtil> requests, HttpServletRequest request, Provider provider,
                                   String rateTenant) {
        requests.when(() -> RequestUtil.validateIP(request, provider, PROVIDER_NAME, rateTenant)).thenReturn("hashed-ip");
        requests.when(() -> RequestUtil.validateBody(BODY, provider, PROVIDER_NAME, "hashed-ip"))
                .thenReturn(Map.of("url", URI_VALUE.toString()));
        requests.when(() -> RequestUtil.validateURI(URI_VALUE.toString(), provider, PROVIDER_NAME, "hashed-ip"))
                .thenReturn(URI_VALUE);
        requests.when(() -> RequestUtil.validateScheme(URI_VALUE, provider, PROVIDER_NAME, "hashed-ip")).thenReturn("https");
        requests.when(() -> RequestUtil.validateHost(URI_VALUE, provider, PROVIDER_NAME, "hashed-ip")).thenReturn(HOST);
        requests.when(() -> RequestUtil.reconstructURI(URI_VALUE, HOST, "https", provider, PROVIDER_NAME, "hashed-ip"))
                .thenReturn(URI_VALUE);
    }

    private static void bareHostInput(MockedStatic<RequestUtil> requests, boolean hasRegistrableDomain) {
        requests.when(() -> RequestUtil.getBareHost(HOST)).thenReturn(BARE_HOST);
        requests.when(() -> RequestUtil.hasRegistrableDomain(HOST)).thenReturn(hasRegistrableDomain);
    }

    private static CircuitBreakerService openCircuit() {
        CircuitBreakerService circuit = mock(CircuitBreakerService.class);
        when(circuit.isOpen(PROVIDER_NAME)).thenReturn(true);
        return circuit;
    }

    private static ProxyHandler handler(Provider provider, MetricsService metrics, CircuitBreakerService circuit,
                                        CloseableHttpClient client) {
        return new ProxyHandler(List.of(provider), metrics, circuit, client);
    }

    private static <T extends Provider> T baseProvider(T provider) {
        when(provider.getDisplayName()).thenReturn(PROVIDER_NAME);
        when(provider.getEndpointName()).thenReturn(ENDPOINT);
        when(provider.isEnabled()).thenReturn(true);
        when(provider.getMethod()).thenReturn(org.apache.hc.core5.http.Method.GET);
        when(provider.buildRequestUrl(anyString())).thenReturn("https://upstream.example/check");
        when(provider.getHeaders()).thenReturn(Map.of());
        when(provider.buildBody(anyString())).thenReturn(null);
        when(provider.isNotFoundValidResponse()).thenReturn(false);
        return provider;
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(anyString())).thenReturn(null);
        return request;
    }

    @SuppressWarnings("unchecked")
    private static ResponseEntity<String> proxy(ProxyHandler handler, HttpServletRequest request, Provider provider,
                                                String tenant) throws Exception {
        return (ResponseEntity<String>) invoke(handler, "proxyRequest",
                new Class<?>[]{byte[].class, HttpServletRequest.class, Provider.class, String.class},
                BODY, request, provider, tenant);
    }

    @SuppressWarnings("unchecked")
    private static ResponseEntity<String> upstream(ProxyHandler handler, Provider provider, String target) throws Exception {
        return (ResponseEntity<String>) invoke(handler, "executeUpstream",
                new Class<?>[]{Provider.class, String.class, String.class}, provider, PROVIDER_NAME, target);
    }

    private static LookupVerdict verdict(ResponseEntity<String> response) throws Exception {
        return (LookupVerdict) invoke(null, "verdictFromResponse", new Class<?>[]{ResponseEntity.class}, response);
    }

    private static Object invoke(Object target, String name, Class<?>[] parameterTypes, Object... arguments) throws Exception {
        Method method = ProxyHandler.class.getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception exception) {
                throw exception;
            }
            throw e;
        }
    }
}
