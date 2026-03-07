/*
 * OspreyProxy - backend code for our proxy server using Spring WebFlux.
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
package net.foulest.ospreyproxy.config;

import net.foulest.ospreyproxy.PrivacyHandler;
import net.foulest.ospreyproxy.ProxyHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * Functional endpoint routing configuration.
 * <p>
 * Replaces the annotation-based {@code @RestController} routing with a
 * {@code RouterFunction} to eliminate per-request overhead from Spring's
 * annotation processing pipeline ({@code ResolvableType}, {@code HandlerMethodArgumentResolverComposite},
 * {@code RequestMappingInfo}, {@code InvocableHandlerMethod}, etc.).
 * <p>
 * Routes are matched top-to-bottom; the catch-all must be last.
 */
@Configuration
public class RouterConfig {

    @Bean
    public RouterFunction<ServerResponse> routes(ProxyHandler proxyHandler, PrivacyHandler privacyHandler) {
        return RouterFunctions.route(RequestPredicates.POST("/alphamountain"), proxyHandler::handleAlphaMountain)
                .andRoute(RequestPredicates.POST("/precisionsec"), proxyHandler::handlePrecisionSec)
                .andRoute(RequestPredicates.GET("/privacy"), privacyHandler::handlePrivacy)
                .andRoute(RequestPredicates.path("/**"), request -> ProxyHandler.RESP_404);
    }
}
