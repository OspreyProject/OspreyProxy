package net.foulest.ospreyproxy.util.check;

import org.jspecify.annotations.NonNull;

/**
 * A single URL prepared once for a /check fan-out. All three key forms are precomputed so that
 * each provider can pick the form matching its keying strategy without reparsing the URL.
 * <p>
 * The forms mirror how ProxyHandler's proxyRequest function keys each provider, so a /check lookup and an
 * extension lookup for the same target share cache entries.
 *
 * @param host The normalized, ASCII, lowercased host with any leading {@code www.} removed.
 * @param bareHost The registrable domain (eTLD+1) of {@code host}, for bare-host providers.
 * @param canonicalUrl The canonical {@code https://host/path} form, for URL-keyed providers.
 * @param hasRegistrableDomain Whether {@code host} has a registrable domain that bare-host providers can use.
 */
public record PreparedUrl(@NonNull String host,
                          @NonNull String bareHost,
                          @NonNull String canonicalUrl,
                          boolean hasRegistrableDomain) {

}
