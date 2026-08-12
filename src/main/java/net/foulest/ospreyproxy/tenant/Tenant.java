package net.foulest.ospreyproxy.tenant;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import net.foulest.ospreyproxy.services.TenantService;
import org.jspecify.annotations.NonNull;

import java.time.Duration;

/**
 * A single tenant: its opaque id and its own aggregate rate budget. The id is what tags logs and
 * metrics; it is an operator-chosen string, never end-user input, so it is safe as a metric label.
 */
public final class Tenant {

    private final String id;
    public final RateSettings rate;
    private final Bucket burstBucket;
    private final Bucket sustainedBucket;

    public Tenant(@NonNull String id, @NonNull RateSettings rate) {
        this.id = id;
        this.rate = rate;

        Bandwidth burst = Bandwidth.builder()
                .capacity(rate.burstCapacity())
                .refillGreedy(rate.burstCapacity(), Duration.ofSeconds(rate.burstWindowSeconds()))
                .build();

        Bandwidth sustained = Bandwidth.builder()
                .capacity(rate.sustainedCapacity())
                .refillGreedy(rate.sustainedCapacity(), Duration.ofSeconds(rate.sustainedWindowSeconds()))
                .build();

        burstBucket = Bucket.builder().addLimit(burst).build();
        sustainedBucket = Bucket.builder().addLimit(sustained).build();
    }

    /**
     * @return The opaque tenant id used to tag logs, metrics, and rate-limit keys.
     */
    public @NonNull String id() {
        return id;
    }

    /**
     * Consumes one token from this tenant's aggregate budget.
     *
     * @return {@code true} if the request is within budget, {@code false} if the tenant is over
     *         either its burst or sustained allowance.
     */
    public boolean tryConsume() {
        boolean burstOk = burstBucket.tryConsume(1);
        boolean sustainedOk = sustainedBucket.tryConsume(1);
        return burstOk && sustainedOk;
    }
}
