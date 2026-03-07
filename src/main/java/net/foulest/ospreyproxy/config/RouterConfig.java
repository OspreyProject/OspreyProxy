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
 *
 * @author Foulest
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
