package net.foulest.ospreyproxy.services;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MetricsServiceTest {

    @Test
    void recordsAllMetricsWithExpectedTags() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        MetricsService metrics = new MetricsService(registry);

        metrics.recordRequest("provider");
        metrics.recordRequest("provider", "tenant");
        metrics.recordCacheHit();
        metrics.recordCacheMiss();
        metrics.recordBlocked("provider", 429);
        metrics.recordBlocked("provider", 503, "tenant");
        metrics.recordUpdateServed("beta", "1.2.3");

        assertThat(registry.get("osprey.requests.total").tag("provider", "provider").tag("tenant", "anonymous")
                .counter().count()).isEqualTo(1);
        assertThat(registry.get("osprey.requests.total").tag("tenant", "tenant").counter().count()).isEqualTo(1);
        assertThat(registry.get("osprey.cache.hits").counter().count()).isEqualTo(1);
        assertThat(registry.get("osprey.cache.misses").counter().count()).isEqualTo(1);
        assertThat(registry.get("osprey.requests.blocked").tag("status", "429").tag("tenant", "anonymous")
                .counter().count()).isEqualTo(1);
        assertThat(registry.get("osprey.requests.blocked").tag("status", "503").tag("tenant", "tenant")
                .counter().count()).isEqualTo(1);
        assertThat(registry.get("osprey.updates.served").tag("channel", "beta").tag("version", "1.2.3")
                .counter().count()).isEqualTo(1);
    }
}
