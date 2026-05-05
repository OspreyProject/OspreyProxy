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
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;

import java.io.IOException;

/**
 * Factory class for creating configured HTTP clients.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class HttpClientFactory {

    /**
     * Retry strategy that retries a single time on {@link ConnectionClosedException} (stale connection),
     * and does not retry on any other exceptions or on any HTTP responses.
     */
    private static final HttpRequestRetryStrategy STALE_CONNECTION_RETRY = new HttpRequestRetryStrategy() {
        @Override
        @Contract(pure = true)
        public boolean retryRequest(HttpRequest request, IOException exception,
                                    int execCount, HttpContext context) {
            return execCount <= 1 && exception instanceof ConnectionClosedException;
        }

        @Override
        @Contract(pure = true)
        public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
            return false;
        }

        @Override
        public TimeValue getRetryInterval(HttpRequest request, IOException exception,
                                          int execCount, HttpContext context) {
            return HttpRequestRetryStrategy.super.getRetryInterval(request, exception, execCount, context);
        }

        @Override
        @Contract(pure = true)
        public TimeValue getRetryInterval(HttpResponse response, int execCount, HttpContext context) {
            return TimeValue.ZERO_MILLISECONDS;
        }
    };

    /**
     * Creates a shared HTTP/2 client with the given timeout settings.
     *
     * @param connectTimeoutSeconds Connection establishment timeout in seconds.
     * @param connectionRequestTimeoutSeconds Timeout for requesting a connection from the connection manager, in seconds.
     * @param responseTimeoutSeconds Socket timeout for waiting for a response, in seconds.
     * @param operationTimeoutSeconds Overall timeout for the entire request execution, in seconds.
     * @return A synchronous {@link CloseableHttpClient} facade over an HTTP/2 async client, where
     *         {@code operationTimeoutSeconds} bounds the total blocking time per request.
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull CloseableHttpClient createHttp2Client(int connectTimeoutSeconds,
                                                                 int connectionRequestTimeoutSeconds,
                                                                 int responseTimeoutSeconds,
                                                                 int operationTimeoutSeconds) {
        CloseableHttpAsyncClient asyncClient = HttpAsyncClients.customHttp2()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(connectTimeoutSeconds))
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(connectionRequestTimeoutSeconds))
                        .setResponseTimeout(Timeout.ofSeconds(responseTimeoutSeconds))
                        .build())
                .disableRedirectHandling()
                .setRetryStrategy(STALE_CONNECTION_RETRY)
                .build();

        asyncClient.start();
        return HttpAsyncClients.classic(asyncClient, Timeout.ofSeconds(operationTimeoutSeconds));
    }

    /**
     * Creates a classic pooled HTTP/1.1 client with the given timeout settings.
     *
     * @param connectTimeoutSeconds Connection establishment timeout in seconds.
     * @param connectionRequestTimeoutSeconds Timeout for requesting a connection from the connection manager, in seconds.
     * @param responseTimeoutSeconds Socket timeout for waiting for a response, in seconds.
     * @return A synchronous pooled {@link CloseableHttpClient} using the classic HTTP/1.1 stack.
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull CloseableHttpClient createHttp1Client(int connectTimeoutSeconds,
                                                                 int connectionRequestTimeoutSeconds,
                                                                 int responseTimeoutSeconds) {
        return HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setDnsResolver(NetworkUtil.DNS_RESOLVER)
                        .setMaxConnTotal(100)
                        .setMaxConnPerRoute(50)
                        .setDefaultConnectionConfig(ConnectionConfig.custom()
                                .setConnectTimeout(Timeout.ofSeconds(connectTimeoutSeconds))
                                .build())
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(connectionRequestTimeoutSeconds))
                        .setResponseTimeout(Timeout.ofSeconds(responseTimeoutSeconds))
                        .build())
                .disableRedirectHandling()
                .setRetryStrategy(STALE_CONNECTION_RETRY)
                .build();
    }
}
