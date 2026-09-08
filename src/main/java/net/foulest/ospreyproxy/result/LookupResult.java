/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
     * Returned when the provider returns a result indicating that the domain is a phishing website.
     */
    PHISHING("phishing"),

    /**
     * Returned when the provider returns a result indicating that the domain is malicious or blocked.
     */
    MALICIOUS("malicious"),

    /**
     * Returned when the provider returns a result indicating that the domain is suspicious or potentially harmful.
     */
    SUSPICIOUS("suspicious"),

    /**
     * Returned when the provider returns a result indicating that the domain is newly registered.
     */
    NEWLY_REGISTERED("newly_registered"),

    /**
     * Returned when the provider returns a result indicating that the domain is associated with dynamic DNS services.
     */
    DYNAMIC_DNS("dynamic_dns"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    PARKED("parked"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    ADULT_CONTENT("adult_content"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    SEX_EDUCATION("sex_education"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    DATING("dating"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    GAMBLING("gambling"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    DRUGS("drugs"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    ALCOHOL_TOBACCO("alcohol_tobacco"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    WEAPONS("weapons"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    HATE_DISCRIMINATION("hate_discrimination"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    VIOLENCE_GORE("violence_gore"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    PIRACY("piracy"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    HACKING("hacking"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    SOCIAL_MEDIA("social_media"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    STREAMING_MEDIA("streaming_media"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    GAMES("games"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    CHAT_MESSAGING("chat_messaging"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    FILE_SHARING("file_sharing"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    SHOPPING_AUCTIONS("shopping_auctions"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    JOB_SEARCH("job_search"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    WEBMAIL("webmail"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    REMOTE_ACCESS("remote_access"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    AI_APPLICATIONS("ai_applications"),

    /**
     * Content policy category emitted when AlphaMountain's category verdict includes the
     * mapped IDs; blockable client-side only when the matching block-category toggle is on.
     */
    CRYPTOCURRENCY("cryptocurrency");

    private final String value;
}
