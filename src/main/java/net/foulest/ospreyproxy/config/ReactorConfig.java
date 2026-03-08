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
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.reactor.netty.NettyReactiveWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Hooks;
import reactor.netty.resources.LoopResources;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Configures Reactor and Netty runtime settings for production performance.
 */
@Slf4j
@Configuration
public class ReactorConfig implements DisposableBean {

    private static final Duration SHUTDOWN_TIMEOUT = Duration.ofSeconds(10);

    // Minimum event loop threads to ensure adequate I/O concurrency for the proxy,
    // even on single or dual-core machines where availableProcessors() * 2 would be too few.
    private static final int MIN_EVENT_LOOP_THREADS = 4;

    // Stored as a field so it can be disposed on shutdown; AtomicReference for
    // thread-safe access between bean initialization (nettyFactory) and shutdown (destroy).
    private final AtomicReference<LoopResources> loopResources = new AtomicReference<>();

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

        // Set Netty resource leak detection level (configurable; default DISABLED for production)
        ResourceLeakDetector.Level level;
        try {
            level = ResourceLeakDetector.Level.valueOf(leakDetectionLevel);
        } catch (IllegalArgumentException ex) {
            log.warn("Invalid leak detection level '{}'; falling back to DISABLED", leakDetectionLevel);
            level = ResourceLeakDetector.Level.DISABLED;
        }
        ResourceLeakDetector.setLevel(level);
    }

    /**
     * Customizes the Netty server with increased event loop threads.
     */
    @Bean
    public NettyReactiveWebServerFactory nettyFactory() {
        NettyReactiveWebServerFactory factory = new NettyReactiveWebServerFactory();
        int processors = Runtime.getRuntime().availableProcessors();
        int threads = Math.max(MIN_EVENT_LOOP_THREADS, processors * 2);
        LoopResources resources = LoopResources.create("http", threads, true);
        LoopResources previous = loopResources.getAndSet(resources);

        // Dispose any previous LoopResources instances
        // (should not happen in normal Spring lifecycle, but just in case).
        // Fire-and-forget is intentional: blocking here would delay server startup
        // to wait for stale event loops to drain. The primary shutdown path in
        // destroy() uses block(SHUTDOWN_TIMEOUT) for the final, authoritative cleanup.
        if (previous != null) {
            log.warn("Replacing existing LoopResources; disposing previous instance");
            previous.disposeLater()
                    .doOnError(err -> log.warn("Failed to dispose previous LoopResources", err))
                    .subscribe();
        }

        factory.addServerCustomizers(server -> server.runOn(resources));
        return factory;
    }

    /**
     * Disposes the LoopResources on application shutdown to release event loop threads.
     */
    @Override
    public void destroy() {
        LoopResources resources = loopResources.get();

        if (resources != null) {
            try {
                resources.disposeLater().block(SHUTDOWN_TIMEOUT);
            } catch (IllegalStateException ex) {
                long seconds = SHUTDOWN_TIMEOUT.getSeconds();
                log.warn("LoopResources disposal did not complete within {} seconds; forcing shutdown", seconds, ex);
            }
        }
    }
}
