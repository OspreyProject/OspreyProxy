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
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.jspecify.annotations.NonNull;

/**
 * Factory class for creating configured HTTP clients.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class HttpClientFactory {

    /**
     * Creates a classic HTTP/2 client backed by an async client with the given timeouts.
     * <p>
     * The underlying async client uses HTTP/2 multiplexing, which handles connection
     * pooling automatically (no explicit max-conn-total or per-route limit needed).
     * Redirect handling and automatic retries are both disabled.
     *
     * @param connectTimeoutSeconds Connection establishment timeout in seconds.
     * @param connectionRequestTimeoutSeconds Timeout for requesting a connection from the connection manager, in seconds.
     * @param responseTimeoutSeconds Socket timeout for waiting for a response, in seconds.
     * @param operationTimeoutSeconds Overall timeout for the entire request execution, in seconds.
     * @return A configured {@link CloseableHttpClient} instance.
     */
    @SuppressWarnings("NestedMethodCall")
    public static @NonNull CloseableHttpClient createHttp2Client(int connectTimeoutSeconds,
                                                                 int connectionRequestTimeoutSeconds,
                                                                 int responseTimeoutSeconds,
                                                                 int operationTimeoutSeconds) {
        CloseableHttpAsyncClient asyncClient = HttpAsyncClients.customHttp2()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(connectTimeoutSeconds))
                        .setValidateAfterInactivity(TimeValue.ofSeconds(1))
                        .build())
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(connectionRequestTimeoutSeconds))
                        .setResponseTimeout(Timeout.ofSeconds(responseTimeoutSeconds))
                        .build())
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .build();

        asyncClient.start();
        return HttpAsyncClients.classic(asyncClient, Timeout.ofSeconds(operationTimeoutSeconds));
    }
}
