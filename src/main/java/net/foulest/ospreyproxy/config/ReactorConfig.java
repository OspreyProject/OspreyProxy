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
