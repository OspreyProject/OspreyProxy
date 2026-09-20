package net.foulest.ospreyproxy.handlers;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.*;

class ContactHandlerTest {

    @Test
    void submitValidatesFieldsBeforeExternalWorkAndFailsClosedWithoutMail() {
        ContactHandler handler = handler(2);
        try {
            assertThat(handler.submit(Map.of(), request()).getStatusCode().value()).isEqualTo(400);
            Map<String, Object> valid = Map.of(
                    "category", "general", "name", "Ada", "email", "ADA@example.com",
                    "message", "This is a complete message.", "token", "ignored");
            assertThat(handler.submit(valid, request()).getStatusCode().value()).isEqualTo(503);
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void submitHandlesNullBodiesAndConfiguredMailDelivery() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        JavaMailSender sender = mailSender();
        ContactHandler handler = handler(jdbc, sender, false, "");
        try {
            assertThat(handler.submit(null, request()).getStatusCode().value()).isEqualTo(400);
            Map<String, Object> valid = Map.of(
                    "category", "business", "name", "Ada", "email", "ada@example.com", "company", "Osprey",
                    "message", "This is a complete message.", "token", "ignored");
            assertThat(handler.submit(valid, request()).getStatusCode().value()).isEqualTo(200);
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void verifyUsesTheRateLimitAndHandlesNumericTimestampsAndQuietPruning() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        ContactHandler handler = handler(jdbc, null, false, "");
        String token = "C".repeat(43);
        try {
            for (int attempt = 0; attempt < 20; attempt++) {
                assertThat(handler.verify(Map.of("token", "invalid"), request()).getStatusCode().value())
                        .isEqualTo(400);
            }
            assertThat(handler.verify(Map.of("token", "invalid"), request()).getStatusCode().value())
                    .isEqualTo(429);
        } finally {
            handler.shutdown();
        }

        JdbcTemplate numericJdbc = mock(JdbcTemplate.class);
        ContactHandler numericHandler = handler(numericJdbc, null, false, "");
        Map<String, Object> row = new HashMap<>();
        row.put("id", 9L);
        row.put("category", "general");
        row.put("name", "Ada");
        row.put("email", "ada@example.com");
        row.put("company", "");
        row.put("message", "Complete message");
        row.put("created_at", 123L);
        when(numericJdbc.queryForList(startsWith("SELECT"), any(Object[].class))).thenReturn(List.of(row));
        when(numericJdbc.update(startsWith("UPDATE"), any(Object[].class))).thenReturn(1);
        when(numericJdbc.update(startsWith("DELETE"), any(Object[].class))).thenReturn(0, 0);
        try {
            assertThat(numericHandler.verify(Map.of("token", token), request()).getStatusCode().value())
                    .isEqualTo(200);
            numericHandler.prune();
        } finally {
            numericHandler.shutdown();
        }
    }

    @Test
    void verifyTreatsAMissingBodyAsAnInvalidToken() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        ContactHandler handler = handler(jdbc, null, false, "");
        try {
            assertThat(handler.verify(null, request()).getStatusCode().value()).isEqualTo(400);
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void turnstileRequestsCoverRemoteIpResponsesAndTransportFailures() throws Exception {
        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn("{\"success\":true}");
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);
        ContactHandler handler = handler(mock(JdbcTemplate.class), null, true, "secret", client, executor());
        HttpServletRequest request = request();
        when(request.getHeader("X-Real-IP")).thenReturn(" 2001:db8::1 ");
        try {
            assertThat(invokeInstance(handler, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(true);
            var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(client).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(requestCaptor.getValue().bodyPublisher().orElseThrow().contentLength()).isPositive();

            when(request.getHeader("X-Real-IP")).thenReturn("not-an-ip");
            assertThat(invokeInstance(handler, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(true);

            when(request.getHeader("X-Real-IP")).thenReturn("x".repeat(46));
            assertThat(invokeInstance(handler, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(true);

            when(response.statusCode()).thenReturn(400);
            assertThat(invokeInstance(handler, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request)).isEqualTo(false);
        } finally {
            handler.shutdown();
        }

        ContactHandler blankToken = handler(mock(JdbcTemplate.class), null, true, "secret", mock(HttpClient.class), executor());
        try {
            assertThat(invokeInstance(blankToken, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "", request())).isEqualTo(false);
        } finally {
            blankToken.shutdown();
        }

        HttpClient interruptedClient = mock(HttpClient.class);
        when(interruptedClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("interrupted"));
        ContactHandler interrupted = handler(mock(JdbcTemplate.class), null, true, "secret", interruptedClient, executor());
        try {
            assertThat(invokeInstance(interrupted, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request())).isEqualTo(false);
            assertThat(Thread.interrupted()).isTrue();
        } finally {
            interrupted.shutdown();
            Thread.interrupted();
        }

        HttpClient failedClient = mock(HttpClient.class);
        when(failedClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("unavailable"));
        ContactHandler failed = handler(mock(JdbcTemplate.class), null, true, "secret", failedClient, executor());
        try {
            assertThat(invokeInstance(failed, "verifyTurnstile",
                    new Class[]{String.class, HttpServletRequest.class}, "captcha", request())).isEqualTo(false);
        } finally {
            failed.shutdown();
        }
    }

    @Test
    void emailHelpersHandleConfiguredAndMissingSendersAndShutdownOutcomes() throws Exception {
        ContactHandler missingSender = handler(mock(JdbcTemplate.class), null, false, "");
        try {
            invokeInstance(missingSender, "sendVerificationEmail",
                    new Class[]{String.class, String.class, String.class}, "ada@example.com", "Ada", "token");
            invokeInstance(missingSender, "forwardToSupport",
                    new Class[]{String.class, String.class, String.class, String.class, String.class, long.class},
                    "general", "Ada", "ada@example.com", "", "Message", 1L);
        } finally {
            missingSender.shutdown();
        }

        JavaMailSender sender = mailSender();
        ContactHandler configuredSender = handler(mock(JdbcTemplate.class), sender, false, "");
        try {
            invokeInstance(configuredSender, "sendVerificationEmail",
                    new Class[]{String.class, String.class, String.class}, "ada@example.com", "Ada", "token");
            invokeInstance(configuredSender, "forwardToSupport",
                    new Class[]{String.class, String.class, String.class, String.class, String.class, long.class},
                    "general", "Ada", "ada@example.com", "", "Message", 1L);
            invokeInstance(configuredSender, "forwardToSupport",
                    new Class[]{String.class, String.class, String.class, String.class, String.class, long.class},
                    "business", "Ada", "ada@example.com", "Osprey", "Message", 1L);
            verify(sender, times(3)).send(any(MimeMessage.class));
        } finally {
            configuredSender.shutdown();
        }

        ThreadPoolExecutor timedOutExecutor = mock(ThreadPoolExecutor.class);
        when(timedOutExecutor.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS)).thenReturn(false);
        when(timedOutExecutor.shutdownNow()).thenReturn(new ArrayList<>());
        ContactHandler timedOut = handler(mock(JdbcTemplate.class), null, false, "", mock(HttpClient.class), timedOutExecutor);
        timedOut.shutdown();
        verify(timedOutExecutor).shutdownNow();

        ThreadPoolExecutor interruptedExecutor = mock(ThreadPoolExecutor.class);
        when(interruptedExecutor.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS))
                .thenThrow(new InterruptedException("interrupted"));
        ContactHandler interrupted = handler(mock(JdbcTemplate.class), null, false, "", mock(HttpClient.class), interruptedExecutor);
        try {
            interrupted.shutdown();
            assertThat(Thread.interrupted()).isTrue();
            verify(interruptedExecutor).shutdownNow();
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void submitRateLimitsAfterValidationAndVerifyRejectsUnknownOrReplayedTokens() {
        ContactHandler handler = handler(1);
        try {
            Map<String, Object> valid = Map.of(
                    "category", "general", "name", "Ada", "email", "ada@example.com",
                    "message", "This is a complete message.", "token", "ignored");
            assertThat(handler.submit(valid, request()).getStatusCode().value()).isEqualTo(503);
            assertThat(handler.submit(valid, request()).getStatusCode().value()).isEqualTo(429);
            assertThat(handler.verify(Map.of("token", "bad"), request()).getStatusCode().value()).isEqualTo(400);
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void privateNormalizersValidationAndEscapingCoverBoundaryCases() throws Exception {
        assertThat(invoke("cleanLine", new Class[]{Object.class, int.class}, " a\u0000b ", 10)).isEqualTo("a b");
        assertThat(invoke("cleanLine", new Class[]{Object.class, int.class}, "abcdef", 3)).isEqualTo("abc");
        assertThat(invoke("cleanBlock", new Class[]{Object.class, int.class}, "a\u0000b\nc", 20)).isEqualTo("a b\nc");
        assertThat(invoke("esc", new Class[]{String.class}, "<&\"'")).isEqualTo("&lt;&amp;&quot;&#39;");
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "unknown", "Name", "name@example.com", "", "long enough")).isNotNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "business", "Name", "name@example.com", "", "long enough")).isNotNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "general", "Name", "name@example.com", "", "long enough")).isNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "general", "", "name@example.com", "", "long enough")).isNotNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "general", "Name", "invalid", "", "long enough")).isNotNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "general", "Name", "", "", "long enough")).isNotNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "msp", "Name", "name@example.com", "", "long enough")).isNotNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "business", "Name", "name@example.com", "Osprey", "long enough")).isNull();
        assertThat(invoke("validate", new Class[]{String.class, String.class, String.class, String.class, String.class},
                "general", "Name", "name@example.com", "", "short")).isNotNull();
        assertThat(invoke("cleanBlock", new Class[]{Object.class, int.class}, "abcdef", 3)).isEqualTo("abc");
        assertThat(invoke("isIpLiteral", new Class[]{String.class}, "")).isEqualTo(false);
        assertThat(invoke("isIpLiteral", new Class[]{String.class}, "2001:db8:A.1")).isEqualTo(true);
        assertThat(invoke("isIpLiteral", new Class[]{String.class}, "127.0.0.x")).isEqualTo(false);
        assertThat(invoke("randomToken", new Class[]{}).toString()).hasSize(43);
        assertThat(invoke("sha256", new Class[]{String.class}, "value"))
                .isEqualTo("cd42404d52ad55ccfa9aca4adc828aa5800ad9d385a0671fbcbf724118320619");
    }

    @Test
    void submitFailsClosedWhenTurnstileIsEnabledWithoutASecret() {
        ContactHandler handler = handler(mock(JdbcTemplate.class), null, true, "");
        try {
            Map<String, Object> valid = Map.of(
                    "category", "general", "name", "Ada", "email", "ada@example.com",
                    "message", "This is a complete message.", "token", "captcha");
            assertThat(handler.submit(valid, request()).getStatusCode().value()).isEqualTo(403);
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void verifyConsumesAValidTokenAndHandlesRowsThatLackANumericTimestamp() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        ContactHandler handler = handler(jdbc, null, false, "");
        String token = "A".repeat(43);
        Map<String, Object> row = new HashMap<>();
        row.put("id", 7L);
        row.put("category", "general");
        row.put("name", "Ada");
        row.put("email", "ada@example.com");
        row.put("company", "");
        row.put("message", "Complete message");
        row.put("created_at", "unknown");
        when(jdbc.queryForList(startsWith("SELECT"), any(Object[].class))).thenReturn(List.of(row));
        when(jdbc.update(startsWith("UPDATE"), any(Object[].class))).thenReturn(1);
        try {
            assertThat(handler.verify(Map.of("token", token), request()).getBody())
                    .containsEntry("ok", true);
            verify(jdbc).update(startsWith("UPDATE"), any(Object[].class));
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void verifyRejectsMissingAndContendedDatabaseRowsAndPrunesBothRetentionGroups() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        ContactHandler handler = handler(jdbc, null, false, "");
        String token = "B".repeat(43);
        try {
            when(jdbc.queryForList(startsWith("SELECT"), any(Object[].class))).thenReturn(List.of());
            assertThat(handler.verify(Map.of("token", token), request()).getStatusCode().value()).isEqualTo(400);

            Map<String, Object> row = Map.of(
                    "id", 8L, "category", "general", "name", "Ada", "email", "ada@example.com",
                    "company", "Osprey", "message", "Complete message", "created_at", 1L);
            when(jdbc.queryForList(startsWith("SELECT"), any(Object[].class))).thenReturn(List.of(row));
            when(jdbc.update(startsWith("UPDATE"), any(Object[].class))).thenReturn(0);
            assertThat(handler.verify(Map.of("token", token), request()).getStatusCode().value()).isEqualTo(400);

            when(jdbc.update(startsWith("DELETE"), any(Object[].class))).thenReturn(1, 2);
            handler.prune();
            verify(jdbc, times(2)).update(startsWith("DELETE"), any(Object[].class));
        } finally {
            handler.shutdown();
        }
    }

    @Test
    void containsMailDeliveryFailures() throws Exception {
        JavaMailSender sender = mock(JavaMailSender.class);
        when(sender.createMimeMessage()).thenThrow(new IllegalStateException("offline"));
        @SuppressWarnings("unchecked")
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(sender);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(1));
        ContactHandler handler = new ContactHandler(mock(JdbcTemplate.class), provider, "from@example.com",
                "to@example.com", "https://site.example", false, "", "http://unused", 1, 1,
                mock(HttpClient.class), executor);
        invokeOn(handler, "sendVerificationEmail", new Class[]{String.class, String.class, String.class},
                "Name", "to@example.com", "token");
        invokeOn(handler, "forwardToSupport",
                new Class[]{String.class, String.class, String.class, String.class, String.class, long.class},
                "other", "Name", "to@example.com", "", "Message", 1L);
        executor.shutdownNow();
    }

    @Test
    void dropsMailTasksWhenTheProductionQueueIsFull() throws Exception {
        @SuppressWarnings("unchecked")
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        ContactHandler handler = new ContactHandler(mock(JdbcTemplate.class), provider,
                "from@example.com", "to@example.com", "https://site.example", false, "",
                "http://unused", 1L, 1L, 1L);

        Field field = ContactHandler.class.getDeclaredField("mailExecutor");
        field.setAccessible(true);
        ThreadPoolExecutor executor = (ThreadPoolExecutor) field.get(handler);

        try {
            AtomicBoolean ran = new AtomicBoolean();
            executor.getRejectedExecutionHandler().rejectedExecution(() -> ran.set(true), executor);
            assertThat(ran).isFalse();
            assertThat(executor.getQueue()).isEmpty();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void reportsUnavailableDigestAlgorithm() throws Exception {
        Method sha256 = ContactHandler.class.getDeclaredMethod("sha256", String.class);
        sha256.setAccessible(true);

        try (MockedStatic<MessageDigest> digests = mockStatic(MessageDigest.class)) {
            digests.when(() -> MessageDigest.getInstance("SHA-256"))
                    .thenThrow(new NoSuchAlgorithmException("missing"));

            assertThatThrownBy(() -> sha256.invoke(null, "value"))
                    .isInstanceOf(InvocationTargetException.class)
                    .hasCauseInstanceOf(IllegalStateException.class);
        }
    }

    private static void invokeOn(Object target, String name, Class<?>[] types, Object... args) throws Exception {
        Method method = target.getClass().getDeclaredMethod(name, types);
        method.setAccessible(true);
        method.invoke(target, args);
    }

    @SuppressWarnings("unchecked")
    private static ContactHandler handler(long capacity) {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        return handler(jdbc, null, false, "", capacity);
    }

    @SuppressWarnings("unchecked")
    private static ContactHandler handler(JdbcTemplate jdbc, JavaMailSender sender, boolean turnstileEnabled,
                                          String turnstileSecret) {
        return handler(jdbc, sender, turnstileEnabled, turnstileSecret, 2);
    }

    @SuppressWarnings("unchecked")
    private static ContactHandler handler(JdbcTemplate jdbc, JavaMailSender sender, boolean turnstileEnabled,
                                          String turnstileSecret, long capacity) {
        ObjectProvider<JavaMailSender> senderProvider = mock(ObjectProvider.class);
        when(senderProvider.getIfAvailable()).thenReturn(sender);
        return new ContactHandler(jdbc, senderProvider, " from@example.com ", " support@example.com ",
                "https://osprey.ac/", turnstileEnabled, turnstileSecret, "http://unused", 1, capacity, 3600);
    }

    @SuppressWarnings("unchecked")
    private static ContactHandler handler(JdbcTemplate jdbc, JavaMailSender sender, boolean turnstileEnabled,
                                          String turnstileSecret, HttpClient client, ThreadPoolExecutor executor) {
        ObjectProvider<JavaMailSender> senderProvider = mock(ObjectProvider.class);
        when(senderProvider.getIfAvailable()).thenReturn(sender);
        return new ContactHandler(jdbc, senderProvider, "from@example.com", "support@example.com",
                "https://osprey.ac", turnstileEnabled, turnstileSecret, "http://unused", 2, 3600,
                client, executor);
    }

    private static ThreadPoolExecutor executor() {
        return new ThreadPoolExecutor(1, 1, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
                new java.util.concurrent.ArrayBlockingQueue<>(1));
    }

    private static JavaMailSender mailSender() {
        JavaMailSender sender = mock(JavaMailSender.class);
        when(sender.createMimeMessage()).thenAnswer(ignored -> new MimeMessage(Session.getInstance(new Properties())));
        return sender;
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("8.8.8.8");
        return request;
    }

    private static Object invoke(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = ContactHandler.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    private static Object invokeInstance(Object target, String name, Class<?>[] types, Object... args) throws Exception {
        Method method = target.getClass().getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(target, args);
    }
}
