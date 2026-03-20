package net.foulest.ospreyproxy.util.dns;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * DNS RR type constants for the record types we care about in filtering responses.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DNSRecords {

    public static final int A = 1;
    public static final int CNAME = 5;
}
