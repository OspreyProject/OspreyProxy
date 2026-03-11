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

import io.netty.util.ResourceLeakDetector;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Hooks;

/**
 * Configures Reactor and Netty runtime settings for production performance.
 * <p>
 * Event loop thread count is configured via application.properties:
 * {@code server.netty.worker-threads} (Spring Boot) or defaults to
 * {@code availableProcessors() * 2} via Reactor Netty's built-in
 * {@code ReactorResourceFactory}. A custom {@code LoopResources} is not
 * needed because Spring's autoconfigured resource factory handles
 * lifecycle (creation and shutdown) automatically, avoiding duplicate
 * thread pools.
 */
@Slf4j
@Configuration
public class ReactorConfig {

    @Value("${ospreyproxy.netty.leak-detection:DISABLED}")
    private String leakDetectionLevel;

    @PostConstruct
    public void configureRuntime() {
        // Disable Reactor's automatic context propagation to reduce per-operator overhead
        Hooks.disableAutomaticContextPropagation();

        // Disable ALL Reactor debug/assembly tracing
        Hooks.resetOnEachOperator();
        Hooks.resetOnOperatorDebug();
        Hooks.resetOnOperatorError();

        // Disables ALL Mono.checkpoint() assembly overhead, including Spring's internal ones
        Hooks.resetOnEachOperator("reactor.core.publisher.Hooks.ON_EACH_OPERATOR");
        System.setProperty("reactor.trace.operatorStacktrace", "false");

        // Set Netty resource leak detection level (configurable; default DISABLED for production)
        ResourceLeakDetector.Level level;
        try {
            level = ResourceLeakDetector.Level.valueOf(leakDetectionLevel);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("Invalid leak detection level '{}'; falling back to DISABLED", leakDetectionLevel);
            level = ResourceLeakDetector.Level.DISABLED;
        }
        ResourceLeakDetector.setLevel(level);
    }
}
