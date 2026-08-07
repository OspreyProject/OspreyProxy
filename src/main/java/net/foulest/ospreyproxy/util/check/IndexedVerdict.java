package net.foulest.ospreyproxy.util.check;

import net.foulest.ospreyproxy.result.LookupVerdict;
import org.jspecify.annotations.NonNull;

/**
 * A verdict paired with the provider index it belongs to, so out-of-order completions map back
 * to the right provider slot.
 *
 * @param index The provider's index within the active list.
 * @param verdict The resolved verdict.
 */
public record IndexedVerdict(int index, @NonNull LookupVerdict verdict) {

}
