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
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.providers.Provider;
import org.jspecify.annotations.NonNull;

/**
 * Utility class for rate limit checks and invalid request handling.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class RateLimitUtil {

    /**
     * Checks if the given {@code hashedIp} is burst-blocked or has exceeded the burst rate limit.
     * Consumes one token from the burst bucket if not already blocked.
     *
     * @param provider The provider to lookup the burst bucket from.
     * @param hashedIp The hashed IP address to lookup and consume from.
     * @param providerName The provider name for logging purposes.
     * @return {@code true} if the IP is blocked or has exceeded the rate limit, {@code false} otherwise.
     */
    static boolean isBurstBlocked(@NonNull Provider provider,
                                  @NonNull String hashedIp,
                                  @NonNull String providerName) {
        String violatorId = provider.getViolatorId(hashedIp);

        // Checks if the IP is already blocked
        if (provider.isBurstBlocked(hashedIp)) {
            return true;
        }

        // Consumes a token to lookup if the IP has hit the rate limit
        if (!provider.getBurstBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] 'Burst' rate limit hit for {}", providerName, violatorId);
            provider.blockBurst(hashedIp);
            return true;
        }
        return false;
    }

    /**
     * Checks if the given {@code hashedIp} is sustained-blocked or has exceeded the sustained rate limit.
     * Consumes one token from the sustained bucket if not already blocked.
     *
     * @param provider The provider to lookup the sustained bucket from.
     * @param hashedIp The hashed IP address to lookup and consume from.
     * @param providerName The provider name for logging purposes.
     * @return {@code true} if the IP is blocked or has exceeded the rate limit, {@code false} otherwise.
     */
    static boolean isSustainedBlocked(@NonNull Provider provider,
                                      @NonNull String hashedIp,
                                      @NonNull String providerName) {
        String violatorId = provider.getViolatorId(hashedIp);

        // Checks if the IP is already blocked
        if (provider.isSustainedBlocked(hashedIp)) {
            return true;
        }

        // Consumes a token to lookup if the IP has hit the rate limit
        if (!provider.getSustainedBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] 'Sustained' rate limit hit for {}", providerName, violatorId);
            provider.blockSustained(hashedIp);
            return true;
        }
        return false;
    }

    /**
     * Consumes one token from the invalid-request bucket for the given {@code hashedIp}.
     * Blocks the {@code hashedIp} if the bucket is exhausted. Logs the rejection reason.
     *
     * @param provider The provider to consume the invalid request token from.
     * @param hashedIp The hashed IP address to lookup and consume from.
     * @param providerName The provider name for logging purposes.
     * @param logMessage The warning message to log when the request is rejected.
     */
    static void rejectInvalidRequest(@NonNull Provider provider,
                                     @NonNull String hashedIp,
                                     @NonNull String providerName,
                                     @NonNull String logMessage) {
        String violatorId = provider.getViolatorId(hashedIp);

        // Consumes a token to lookup if the IP has hit the rate limit
        if (!provider.getInvalidRequestBucket(hashedIp).tryConsume(1)) {
            log.warn("[{}] 'Invalid request' rate limit hit for {}", providerName, violatorId);
            provider.blockInvalidRequest(hashedIp);
            throw new StatusCodeException(ErrorUtil.RESP_429);
        }

        // If the IP is not yet blocked, log the reason
        log.warn("[{}] {}", providerName, logMessage);
    }
}
