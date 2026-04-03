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

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Enum representing the possible results of a lookup operation from a provider.
 */
@Getter
@AllArgsConstructor
public enum LookupResult {

    /**
     * Returned when an error occurs during the lookup process.
     */
    FAILED("failed"),

    /**
     * Returned when the provider returns a 429 Too Many Requests status.
     */
    RATE_LIMITED("rate_limited"),

    /**
     * Returned when the provider returns a result indicating that the domain is safe and allowed.
     */
    ALLOWED("allowed"),

    /**
     * Returned when the provider returns a result indicating that the domain is malicious or blocked.
     */
    MALICIOUS("malicious"),

    /**
     * Returned when the provider returns a result indicating that the domain is a phishing website.
     */
    PHISHING("phishing"),
    /**
     * Returned when the provider returns a result indicating that the domain is untrusted or suspicious.
     */
    UNTRUSTED("untrusted"),

    /**
     * Returned when the provider returns a result indicating that the domain contains adult content.
     */
    ADULT_CONTENT("adult_content");

    private final String value;
}
