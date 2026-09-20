/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.util;

import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.http.protocol.BasicHttpContext;
import org.apache.hc.core5.http2.H2Error;
import org.apache.hc.core5.http2.H2StreamResetException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;

class HttpClientFactoryTest {

    @Test
    void staleConnectionRetryOnlyRetriesThePermittedFailuresOnce() throws Exception {
        HttpRequestRetryStrategy retry = retryStrategy();
        HttpRequest request = new BasicHttpRequest("GET", "/");
        BasicHttpContext context = new BasicHttpContext();

        Assertions.assertThat(retry.retryRequest(request, new ConnectionClosedException(), 1, context)).isTrue();
        Assertions.assertThat(retry.retryRequest(request, new ConnectionClosedException(), 2, context)).isFalse();
        Assertions.assertThat(retry.retryRequest(request, new IOException("other"), 1, context)).isFalse();
        Assertions.assertThat(retry.retryRequest(request,
                new H2StreamResetException(H2Error.REFUSED_STREAM, "refused"), 1, context)).isTrue();
        Assertions.assertThat(retry.retryRequest(request,
                new IOException("wrapped", new H2StreamResetException(H2Error.REFUSED_STREAM, "refused")),
                1, context)).isTrue();
        Assertions.assertThat(retry.retryRequest(request,
                new H2StreamResetException(H2Error.CANCEL, "cancelled"), 1, context)).isFalse();
        Assertions.assertThat(retry.retryRequest(new BasicHttpResponse(503), 1, context)).isFalse();
        Assertions.assertThat(retry.getRetryInterval(request, new IOException(), 1, context).toMilliseconds()).isZero();
        Assertions.assertThat(retry.getRetryInterval(new BasicHttpResponse(503), 1, context).toMilliseconds()).isZero();
    }

    @Test
    void factoryCreatesClosableClientsForAllSupportedStacks() throws Exception {
        try (CloseableHttpClient http2 = HttpClientFactory.createHttp2Client(1, 1, 1, 1);
             CloseableHttpClient negotiating = HttpClientFactory.createNegotiatingClient(1, 1, 1, 1);
             CloseableHttpClient http1 = HttpClientFactory.createHttp1Client(1, 1, 1)) {
            Assertions.assertThat(http2).isNotNull();
            Assertions.assertThat(negotiating).isNotNull();
            Assertions.assertThat(http1).isNotNull();
        }
    }

    private static HttpRequestRetryStrategy retryStrategy() throws Exception {
        Field field = HttpClientFactory.class.getDeclaredField("STALE_CONNECTION_RETRY");
        field.setAccessible(true);
        return (HttpRequestRetryStrategy) field.get(null);
    }
}
