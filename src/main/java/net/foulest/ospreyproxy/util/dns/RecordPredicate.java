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
package net.foulest.ospreyproxy.util.dns;

/**
 * Functional interface for testing DNS answer records in the raw response bytes.
 * The predicate takes the RR type and RDATA bytes as input and returns a boolean
 * indicating whether the record matches the filtering criteria.
 */
@FunctionalInterface
public interface RecordPredicate {

    /**
     * Tests whether a DNS answer record matches the criteria defined by this predicate.
     *
     * @param rrType The RR type of the DNS answer record (e.g., A, AAAA, CNAME, etc.) as an integer.
     * @param rdata The raw RDATA bytes of the DNS answer record, which may need to be parsed according to the RR type.
     * @return true if the record matches the criteria defined by this predicate, false otherwise.
     */
    boolean test(int rrType, byte[] rdata);
}
