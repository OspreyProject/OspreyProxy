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
package net.foulest.ospreyproxy.result;

import org.jetbrains.annotations.Contract;
import org.jspecify.annotations.NonNull;

import java.util.*;

/**
 * An immutable, non-empty result of a single lookup.
 */
public final class LookupVerdict {

    /**
     * Severity ranking, most severe first. Determines both the iteration order of
     * {@link #results()} and which element {@link #primary()} returns. Kept independent
     * of the {@link LookupResult} enum's declaration order so the enum can be reordered
     * without silently changing verdict semantics.
     */
    private static final List<LookupResult> SEVERITY_ORDER = List.of(
            LookupResult.PHISHING,
            LookupResult.MALICIOUS,
            LookupResult.SUSPICIOUS,
            LookupResult.NEWLY_REGISTERED,
            LookupResult.DYNAMIC_DNS,
            LookupResult.ALLOWED,
            LookupResult.RATE_LIMITED,
            LookupResult.FAILED
    );

    /**
     * Shared singleton for a failed lookup.
     */
    public static final LookupVerdict FAILED = new LookupVerdict(List.of(LookupResult.FAILED));

    /**
     * Shared singleton for a rate-limited lookup.
     */
    public static final LookupVerdict RATE_LIMITED = new LookupVerdict(List.of(LookupResult.RATE_LIMITED));

    /**
     * Shared singleton for an allowed (clean) lookup.
     */
    public static final LookupVerdict ALLOWED = new LookupVerdict(List.of(LookupResult.ALLOWED));

    /**
     * Non-empty, deduplicated, severity-ordered, immutable list of results.
     */
    private final List<LookupResult> results;

    private LookupVerdict(@NonNull List<LookupResult> results) {
        this.results = results;
    }

    /**
     * Returns a verdict wrapping a single result, reusing a shared singleton where possible.
     *
     * @param result The single result to wrap.
     * @return A verdict containing exactly {@code result}.
     */
    @Contract(pure = true)
    public static @NonNull LookupVerdict of(@NonNull LookupResult result) {
        return switch (result) {
            case FAILED -> FAILED;
            case RATE_LIMITED -> RATE_LIMITED;
            case ALLOWED -> ALLOWED;
            default -> new LookupVerdict(List.of(result));
        };
    }

    /**
     * Returns a verdict containing the given results, deduplicated and severity-ordered.
     * An empty argument list collapses to {@link #FAILED}.
     *
     * @param results The results to include.
     * @return A non-empty verdict.
     */
    @Contract(pure = true)
    public static @NonNull LookupVerdict of(@NonNull LookupResult @NonNull ... results) {
        return of(Arrays.asList(results));
    }

    /**
     * Returns a verdict containing the given results, deduplicated and severity-ordered.
     * A {@code null} or empty collection collapses to {@link #FAILED}.
     *
     * @param results The results to include.
     * @return A non-empty verdict.
     */
    @Contract(pure = true)
    public static @NonNull LookupVerdict of(Collection<LookupResult> results) {
        if (results == null || results.isEmpty()) {
            return FAILED;
        }

        // EnumSet deduplicates; explicit sort imposes severity order (EnumSet iterates by ordinal).
        EnumSet<LookupResult> unique = EnumSet.copyOf(results);

        if (unique.size() == 1) {
            return of(unique.iterator().next());
        }

        List<LookupResult> ordered = new ArrayList<>(unique);
        ordered.sort((a, b) -> Integer.compare(SEVERITY_ORDER.indexOf(a), SEVERITY_ORDER.indexOf(b)));
        return new LookupVerdict(List.copyOf(ordered));
    }

    /**
     * @return The deduplicated, severity-ordered, immutable list of results. Never empty.
     */
    @Contract(pure = true)
    public @NonNull List<LookupResult> results() {
        return results;
    }

    /**
     * @return The string values of {@link #results()}, in the same order. Suitable for
     *         serializing directly as the {@code "results"} JSON array.
     */
    @Contract(pure = true)
    public @NonNull List<String> values() {
        List<String> out = new ArrayList<>(results.size());

        for (LookupResult result : results) {
            out.add(result.getValue());
        }
        return out;
    }

    /**
     * @return The single most severe result, used for the backward-compatible {@code "result"} scalar.
     */
    @Contract(pure = true)
    public @NonNull LookupResult primary() {
        return results.getFirst();
    }

    /**
     * @return {@code true} if this verdict is exactly {@link LookupResult#FAILED}.
     */
    @Contract(pure = true)
    public boolean isFailed() {
        return results.size() == 1 && results.getFirst() == LookupResult.FAILED;
    }

    /**
     * @return {@code true} if this verdict is exactly {@link LookupResult#RATE_LIMITED}.
     */
    @Contract(pure = true)
    public boolean isRateLimited() {
        return results.size() == 1 && results.getFirst() == LookupResult.RATE_LIMITED;
    }

    /**
     * @return {@code true} if this verdict is exactly {@link LookupResult#ALLOWED}, i.e. a clean
     *         result with no threat categories. Used to route cache writes to the long-TTL allow cache.
     */
    @Contract(pure = true)
    public boolean isAllowedOnly() {
        return results.size() == 1 && results.getFirst() == LookupResult.ALLOWED;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj instanceof LookupVerdict other && results.equals(other.results);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(results);
    }

    @Override
    public @NonNull String toString() {
        return "LookupVerdict" + results;
    }
}
