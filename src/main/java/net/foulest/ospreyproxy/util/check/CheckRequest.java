package net.foulest.ospreyproxy.util.check;

import org.jspecify.annotations.Nullable;

/**
 * The request body for a scan.
 *
 * @param url The URL to scan.
 * @param token The Cloudflare Turnstile token.
 */
public record CheckRequest(@Nullable String url, @Nullable String token) {

}
