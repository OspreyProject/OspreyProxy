package net.foulest.ospreyproxy.handlers;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.tenant.Tenant;
import net.foulest.ospreyproxy.tenant.TenantService;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.RequestUtil;
import net.foulest.ospreyproxy.util.list.Descriptor;
import net.foulest.ospreyproxy.util.list.LocalListUtil;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;

class SubmitHandlerTest {

    @Test
    void submitRejectsMissingWrongAndNonSubmissionCredentials() {
        TenantService tenants = mock(TenantService.class);
        SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 10, 10);

        assertStatus(() -> handler.submit("missing", null, "{}".getBytes(StandardCharsets.UTF_8), request()), 401);

        Tenant wrongFeed = mock(Tenant.class);
        when(wrongFeed.id()).thenReturn("submit-other");
        when(tenants.resolve("token")).thenReturn(wrongFeed);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{}".getBytes(StandardCharsets.UTF_8), request()), 401);
    }

    @Test
    void submitRejectsTenantExhaustionAndAllInvalidBodyShapes() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(false);
        when(tenants.resolve("token")).thenReturn(tenant);
        SubmitHandler handler = new SubmitHandler(tenants, 20, 3600, 10, 2);

        when(tenant.tryConsume()).thenReturn(false);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{}".getBytes(StandardCharsets.UTF_8), request()), 429);
        when(tenant.tryConsume()).thenReturn(true);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{".getBytes(StandardCharsets.UTF_8), request()), 400);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{}".getBytes(StandardCharsets.UTF_8), request()), 400);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{\"urls\":[]}".getBytes(StandardCharsets.UTF_8), request()), 400);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{\"urls\":[\"a\",\"b\",\"c\"]}".getBytes(StandardCharsets.UTF_8), request()), 400);
        assertStatus(() -> handler.submit("acomics", "Bearer token", "{\"urls\":[1]}".getBytes(StandardCharsets.UTF_8), request()), 400);
    }

    @Test
    void submitAppliesIpLimitBeforeAuthentication() {
        SubmitHandler handler = new SubmitHandler(mock(TenantService.class), 1, 3600, 10, 10);
        assertStatus(() -> handler.submit("acomics", null, null, request()), 401);
        assertStatus(() -> handler.submit("acomics", null, null, request()), 429);
    }

    @Test
    void submitAcceptsAndRefundsEntriesWithoutTouchingTheFilesystem() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);
        HttpServletRequest request = request();

        try (MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class);
             MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class)) {
            requests.when(() -> RequestUtil.hashClientIp(request, "submit")).thenReturn("ip");
            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("one", "two"), "ip"))
                    .thenReturn(Map.of("accepted", 1, "duplicates", 1, "rejected", 0));

            SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 2, 2);
            String body = "{\"urls\":[\"one\",\"two\"]}";
            Assertions.assertThat(handler.submit("acomics", "Bearer token",
                            body.getBytes(StandardCharsets.UTF_8), request).getBody())
                    .contains("\"accepted\":1", "\"duplicates\":1");
        }
    }

    @Test
    void submitDoesNotWarnForRejectedOrSmallBatches() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);
        HttpServletRequest request = request();

        try (MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class);
             MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class)) {
            requests.when(() -> RequestUtil.hashClientIp(request, "submit")).thenReturn("ip");
            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("rejected"), "ip"))
                    .thenReturn(Map.of("accepted", 0, "duplicates", 0, "rejected", 1));
            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("accepted"), "ip"))
                    .thenReturn(Map.of("accepted", 1, "duplicates", 0, "rejected", 0));

            SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 10, 10);
            Assertions.assertThat(handler.submit("acomics", "Bearer token",
                            "{\"urls\":[\"rejected\"]}".getBytes(StandardCharsets.UTF_8), request).getStatusCode().value())
                    .isEqualTo(200);
            Assertions.assertThat(handler.submit("acomics", "Bearer token",
                            "{\"urls\":[\"accepted\"]}".getBytes(StandardCharsets.UTF_8), request).getStatusCode().value())
                    .isEqualTo(200);
        }
    }

    @Test
    void submitAcceptsAPositiveBatchBelowTheAnomalyThreshold() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);
        HttpServletRequest request = request();

        try (MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class);
             MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class)) {
            requests.when(() -> RequestUtil.hashClientIp(request, "submit")).thenReturn("ip");
            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("accepted"), "ip"))
                    .thenReturn(Map.of("accepted", 1, "duplicates", 0, "rejected", 0));

            SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 100, 10);
            Assertions.assertThat(handler.submit("acomics", "Bearer " + "token",
                            "{\"urls\":[\"accepted\"]}".getBytes(StandardCharsets.UTF_8), request)
                    .getStatusCode().value()).isEqualTo(200);
        }
    }

    @Test
    void submitRejectsNonSubmissionDescriptorsAndDailyBudgetExhaustion() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-openphish");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);

        try (MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class)) {
            lists.when(() -> LocalListUtil.findByEndpointName("openphish")).thenReturn(Descriptor.OPEN_PHISH);
            SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 1, 2);
            assertStatus(() -> handler.submit("openphish", "Bearer token",
                    "{\"urls\":[\"one\"]}".getBytes(StandardCharsets.UTF_8), request()), 401);

            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            when(tenant.id()).thenReturn("submit-acomics");
            when(tenant.tryConsume()).thenReturn(false);
            assertStatus(() -> handler.submit("acomics", "Bearer token",
                    "{\"urls\":[\"one\",\"two\"]}".getBytes(StandardCharsets.UTF_8), request()), 429);
        }
    }

    @Test
    void submitCoversAuthorizationBodyAndDailyBudgetBoundaries() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);
        SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 1, 2);
        HttpServletRequest request = request();

        assertStatus(() -> handler.submit("acomics", "Basic token",
                "{}".getBytes(StandardCharsets.UTF_8), request), 401);

        try (MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class);
             MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class)) {
            requests.when(() -> RequestUtil.hashClientIp(request, "submit")).thenReturn("ip");
            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(null);
            assertStatus(() -> handler.submit("acomics", "Bearer token",
                    "{}".getBytes(StandardCharsets.UTF_8), request), 401);

            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            assertStatus(() -> handler.submit("acomics", "Bearer token", null, request), 400);
            assertStatus(() -> handler.submit("acomics", "Bearer token", new byte[0], request), 400);
            assertStatus(() -> handler.submit("acomics", "Bearer token",
                    "{\"urls\":[]}".getBytes(StandardCharsets.UTF_8), request), 400);
            assertStatus(() -> handler.submit("acomics", "Bearer token",
                    "{\"urls\":[\"one\",\"two\",\"three\"]}".getBytes(StandardCharsets.UTF_8), request), 400);

            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("one"), "ip"))
                    .thenReturn(Map.of("accepted", 1, "duplicates", 0, "rejected", 0));
            Assertions.assertThat(handler.submit("acomics", "Bearer token",
                            "{\"urls\":[\"one\"]}".getBytes(StandardCharsets.UTF_8), request).getStatusCode().value())
                    .isEqualTo(200);
            assertStatus(() -> handler.submit("acomics", "Bearer token",
                    "{\"urls\":[\"two\"]}".getBytes(StandardCharsets.UTF_8), request), 429);
        }
    }

    @Test
    void submitReturnsServerErrorWhenPersistenceFails() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);
        HttpServletRequest request = request();

        try (MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class);
             MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class)) {
            requests.when(() -> RequestUtil.hashClientIp(request, "submit")).thenReturn("ip");
            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("one"), "ip"))
                    .thenThrow(new IOException("disk unavailable"));

            assertStatus(() -> handler(tenants).submit("acomics", "Bearer token",
                    "{\"urls\":[\"one\"]}".getBytes(StandardCharsets.UTF_8), request), 500);
        }
    }

    @Test
    void submitReturnsServerErrorWhenTheCountsCannotBeSerialized() {
        TenantService tenants = mock(TenantService.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.id()).thenReturn("submit-acomics");
        when(tenant.tryConsume()).thenReturn(true);
        when(tenants.resolve("token")).thenReturn(tenant);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("9.9.9.9");

        try (MockedStatic<LocalListUtil> lists = mockStatic(LocalListUtil.class);
             MockedStatic<RequestUtil> requests = mockStatic(RequestUtil.class)) {
            requests.when(() -> RequestUtil.hashClientIp(request, "submit")).thenReturn("ip");
            lists.when(() -> LocalListUtil.findByEndpointName("acomics")).thenReturn(Descriptor.ACOMICS);
            lists.when(() -> LocalListUtil.submit(Descriptor.ACOMICS, List.of("one"), "ip"))
                    .thenReturn(unserializableCounts());

            SubmitHandler handler = new SubmitHandler(tenants, 10, 3600, 10, 10);
            Assertions.assertThat(handler.submit("acomics", "Bearer " + "token",
                            "{\"urls\":[\"one\"]}".getBytes(StandardCharsets.UTF_8), request))
                    .isSameAs(ErrorUtil.RESP_500);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Integer> unserializableCounts() {
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("accepted", 1);
        counts.put("duplicates", 0);
        counts.put("rejected", 0);
        counts.put("detail", new Unserializable());
        return (Map<String, Integer>) (Map<String, ?>) counts;
    }

    @SuppressWarnings("unused")
    public static final class Unserializable {

        public String getValue() {
            throw new IllegalStateException("cannot be serialized");
        }
    }

    private static SubmitHandler handler(TenantService tenants) {
        return new SubmitHandler(tenants, 10, 3600, 10, 10);
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("9.9.9.9");
        return request;
    }

    private static void assertStatus(ThrowingCall call, int expected) {
        StatusCodeException exception = Assertions.catchThrowableOfType(call::run, StatusCodeException.class);
        Assertions.assertThat(exception.getStatus().getStatusCode().value()).isEqualTo(expected);
    }

    @FunctionalInterface
    private interface ThrowingCall {

        void run();
    }
}
