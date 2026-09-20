package net.foulest.ospreyproxy.handlers;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.util.ErrorUtil;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReportingTestHandlerTest {

    private static final String TOKEN = "12345678-1234-1234-1234-123456789012";

    @Test
    void receiveRejectsInvalidTokensOversizedBodiesAndMalformedJson() {
        ReportingTestHandler handler = handler(10);
        Assertions.assertThat(handler.receive("short", "{}", request(false))).isSameAs(ErrorUtil.RESP_400);
        Assertions.assertThat(handler.receive(TOKEN, "{", request(false))).isSameAs(ErrorUtil.RESP_400);
        Assertions.assertThat(handler.receive(TOKEN, "x".repeat(262_145), request(false))).isSameAs(ErrorUtil.RESP_400);
    }

    @Test
    void receiveAndPollPreservePayloadAndAuthorizationPresence() {
        ReportingTestHandler handler = handler(10);
        Assertions.assertThat(handler.receive(TOKEN, "{\"event\":\"heartbeat\"}", request(true)).getStatusCode().value())
                .isEqualTo(200);

        ResponseEntity<String> poll = handler.poll(TOKEN, request(false));
        Assertions.assertThat(poll.getBody())
                .contains("\"event\":\"heartbeat\"", "\"authPresent\":true");
        Assertions.assertThat(poll.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test
    void receiveRetainsOnlyNewestThirtyPayloadsAndRateLimits() {
        ReportingTestHandler handler = handler(100);
        for (int i = 0; i < 31; i++) {
            handler.receive(TOKEN, "{\"number\":" + i + "}", request(false));
        }
        String payloads = handler.poll(TOKEN, request(false)).getBody();
        Assertions.assertThat(payloads).doesNotContain("\"number\":0").contains("\"number\":30");

        ReportingTestHandler limited = handler(1);
        limited.poll(TOKEN, request(false));
        Assertions.assertThat(limited.poll(TOKEN, request(false))).isSameAs(ErrorUtil.RESP_429);
    }

    private static ReportingTestHandler handler(long capacity) {
        return new ReportingTestHandler(30, 10, capacity, 3600);
    }

    private static HttpServletRequest request(boolean authorization) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("1.1.1.1");
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorization ? "Bearer value" : null);
        return request;
    }
}
