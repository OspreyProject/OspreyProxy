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
import org.springframework.boot.reactor.netty.NettyReactiveWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Hooks;
import reactor.netty.resources.LoopResources;

/**
 * Configures Reactor and Netty runtime settings for production performance.
 */
@Configuration
public class ReactorConfig {

    @PostConstruct
    public void configureRuntime() {
        // Disable Reactor's automatic context propagation to reduce per-operator overhead
        Hooks.disableAutomaticContextPropagation();

        // Disable ALL Reactor debug/assembly tracing
        Hooks.resetOnEachOperator();
        Hooks.resetOnOperatorDebug();
        Hooks.resetOnOperatorError();

        // Disable Netty resource leak detection in production
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);

        // Ensure Reactor Netty access log is disabled via system property
        System.setProperty("reactor.netty.http.server.accessLogEnabled", "false");
    }

    /**
     * Customizes the Netty server with increased event loop threads.
     */
    @Bean
    public NettyReactiveWebServerFactory nettyFactory() {
        NettyReactiveWebServerFactory factory = new NettyReactiveWebServerFactory();
        int processors = Runtime.getRuntime().availableProcessors();
        int threads = Math.max(4, processors * 2);
        LoopResources loopResources = LoopResources.create("http", threads, true);
        factory.addServerCustomizers(server -> server.runOn(loopResources));
        return factory;
    }
}
