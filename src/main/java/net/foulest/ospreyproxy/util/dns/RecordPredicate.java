package net.foulest.ospreyproxy.util.dns;

/**
 * Functional interface for testing DNS answer records in the raw response bytes.
 * The predicate takes the RR type and RDATA bytes as input and returns a boolean
 * indicating whether the record matches the filtering criteria.
 */
@FunctionalInterface
public interface RecordPredicate {

    boolean test(int rrType, byte[] rdata);
}
