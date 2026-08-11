package net.foulest.ospreyproxy.util.check;

import org.jspecify.annotations.Nullable;

/**
 * The request body for a scan.
 *
 * @param url The URL to scan.
 * @param token The Cloudflare Turnstile token.
 * @param force Whether to bypass any stored result and force a fresh scan. Absent means {@code false}.
 */
public record CheckRequest(@Nullable String url, @Nullable String token, boolean force) {

}
