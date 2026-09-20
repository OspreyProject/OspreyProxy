package net.foulest.ospreyproxy.handlers;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.store.ScanRecord;
import net.foulest.ospreyproxy.store.ScanStore;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class ResultHandlerTest {

    @Test
    void resultRejectsInvalidUrlAndRateLimitExhaustion() {
        ScanStore store = mock(ScanStore.class);
        ResultHandler handler = new ResultHandler(store, 60, "", 10, 1, 3600);

        StatusCodeException invalid = Assertions.catchThrowableOfType(
                () -> handler.result("localhost", request()), StatusCodeException.class);
        Assertions.assertThat(invalid.getStatus().getStatusCode().value()).isEqualTo(400);

        StatusCodeException limited = Assertions.catchThrowableOfType(
                () -> handler.result("example.com", request()), StatusCodeException.class);
        Assertions.assertThat(limited.getStatus().getStatusCode().value()).isEqualTo(429);
    }

    @Test
    void resultReturnsNotFoundAndFreshAndStaleRecords() {
        ScanStore store = mock(ScanStore.class);
        ResultHandler handler = new ResultHandler(store, 1, "", 10, 10, 3600);
        when(store.get("https://missing.example")).thenReturn(null);
        ResponseEntity<String> missing = handler.result("missing.example", request());
        Assertions.assertThat(missing.getBody()).contains("\"found\":false", "https://missing.example");

        when(store.get("https://fresh.example")).thenReturn(record("fresh.example", System.currentTimeMillis()));
        ResponseEntity<String> fresh = handler.result("fresh.example", request());
        Assertions.assertThat(fresh.getBody()).contains("\"found\":true", "\"fresh\":true");

        when(store.get("https://stale.example")).thenReturn(record("stale.example", 0));
        ResponseEntity<String> stale = handler.result("stale.example", request());
        Assertions.assertThat(stale.getBody()).contains("\"fresh\":false");
    }

    @Test
    void indexFeedHidesMissingOrIncorrectSecretsAndReturnsRequestedRecords() {
        ScanStore store = mock(ScanStore.class);
        ResultHandler handler = new ResultHandler(store, 60, "token", 5, 10, 60);

        StatusCodeException missing = Assertions.catchThrowableOfType(
                () -> handler.indexFeed(null, null), StatusCodeException.class);
        StatusCodeException incorrect = Assertions.catchThrowableOfType(
                () -> handler.indexFeed("Bearer wrong", null), StatusCodeException.class);
        Assertions.assertThat(missing.getStatus().getStatusCode().value()).isEqualTo(404);
        Assertions.assertThat(incorrect.getStatus().getStatusCode().value()).isEqualTo(404);

        when(store.findIndexableSince(7L, 5)).thenReturn(List.of(record("feed.example", 99)));
        ResponseEntity<String> response = handler.indexFeed("Bearer token", 7L);
        Assertions.assertThat(response.getBody()).contains("\"count\":1", "feed.example");
        verify(store).findIndexableSince(7L, 5);
    }

    @Test
    void indexFeedRejectsAnUnsetSecretAndUsesZeroForAnOmittedSinceValue() {
        ScanStore store = mock(ScanStore.class);
        ResultHandler unset = new ResultHandler(store, 60, " ", 5, 10, 60);

        StatusCodeException hidden = Assertions.catchThrowableOfType(
                () -> unset.indexFeed("******", null), StatusCodeException.class);
        Assertions.assertThat(hidden.getStatus().getStatusCode().value()).isEqualTo(404);

        ResultHandler configured = new ResultHandler(store, 60, "token", 5, 10, 60);
        when(store.findIndexableSince(0L, 5)).thenReturn(List.of());
        Assertions.assertThat(configured.indexFeed("Bearer " + "token", null).getBody()).contains("\"count\":0");
        verify(store).findIndexableSince(0L, 5);
    }

    @Test
    void convertsSerializationFailuresToServerErrors() throws Exception {
        Method json = ResultHandler.class.getDeclaredMethod("json", Map.class);
        json.setAccessible(true);
        Map<String, Object> cyclic = new HashMap<>();
        cyclic.put("self", cyclic);
        assertThatThrownBy(() -> json.invoke(null, cyclic))
                .isInstanceOf(InvocationTargetException.class)
                .hasCauseInstanceOf(StatusCodeException.class);
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("8.8.4.4");
        return request;
    }

    private static ScanRecord record(String host, long scannedAt) {
        return new ScanRecord("https://" + host, host, host, "malicious",
                Map.of("provider", List.of("malicious")), 1, 1, scannedAt, scannedAt, 1, true, null);
    }
}
