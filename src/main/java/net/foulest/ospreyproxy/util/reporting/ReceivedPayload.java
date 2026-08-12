package net.foulest.ospreyproxy.util.reporting;

import org.jspecify.annotations.NonNull;

/**
 * One received POST: when it arrived, whether it carried an Authorization header, and the raw
 * JSON body exactly as sent.
 *
 * @param receivedAt Epoch milliseconds the payload arrived.
 * @param authPresent Whether the request carried an Authorization header.
 * @param rawJson The body as sent, already validated to parse as JSON.
 */
public record ReceivedPayload(long receivedAt, boolean authPresent, @NonNull String rawJson) {

}
