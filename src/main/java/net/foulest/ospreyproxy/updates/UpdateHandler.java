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
package net.foulest.ospreyproxy.updates;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.services.MetricsService;
import net.foulest.ospreyproxy.util.ErrorUtil;
import net.foulest.ospreyproxy.util.JacksonUtil;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

/**
 * The extension-distribution surface of a self-hosted proxy: a Chromium CRX update server.
 * <p>
 * Managed browsers are force-installed with an {@code update_url} that points at one of this server's
 * per-channel manifests, for example {@code https://updates.example.com/updates/stable.xml}. The browser
 * polls that URL on its own schedule; the manifest names the version the channel currently offers and the
 * absolute {@code codebase} URL of the CRX. Pointing a subset of a client's endpoints at
 * {@code /updates/beta.xml} instead stages an update to that subset; pinning a channel to an exact
 * version in {@code channels.json} holds a client on a known-good build. See {@code docs/updates.md}.
 * <p>
 * Every endpoint here is a {@code GET} under the multi-segment {@code /updates/} path, so it is never
 * treated as an extension-facing provider endpoint and never requires a tenant key: browsers fetching
 * updates cannot present one. The whole controller exists only when the update server is enabled, since
 * it is conditional on {@link UpdateService}.
 */
@Slf4j
@RestController
@ConditionalOnBean(UpdateService.class)
public class UpdateHandler {

    private static final String CONTEXT = "updates";

    // CRX filenames are operator-authored and version-stamped; constrain them to a safe shape and require
    // the .crx suffix. A download is additionally accepted only when the name belongs to a catalogued release.
    private static final Pattern CRX_NAME = Pattern.compile("^[A-Za-z0-9._-]+\\.crx$");

    private static final MediaType CRX_TYPE = MediaType.parseMediaType("application/x-chrome-extension");
    private static final MediaType RSS_TYPE = MediaType.parseMediaType("application/rss+xml");
    private static final MediaType XML_UTF8 = new MediaType(MediaType.APPLICATION_XML, StandardCharsets.UTF_8);

    private final UpdateService updateService;
    private final MetricsService metricsService;

    /**
     * @param updateService The catalog of releases and channel pins.
     * @param metricsService The metrics registry, used to count served update offers per channel.
     */
    public UpdateHandler(@NonNull UpdateService updateService, @NonNull MetricsService metricsService) {
        this.updateService = updateService;
        this.metricsService = metricsService;
    }

    /**
     * Returns the Chromium update manifest for a channel. An unknown channel is a 404 so a misrouted
     * {@code update_url} is visible to the operator; a known channel with no resolvable build returns a
     * valid {@code noupdate} manifest so endpoints simply keep their current version during a catalog gap.
     *
     * @param channel The channel name from the path.
     * @param request The incoming request, used to derive a base URL and the requested application id.
     * @return An XML update manifest.
     */
    @GetMapping(value = "/updates/{channel}.xml")
    public @NonNull ResponseEntity<String> manifest(@PathVariable @NonNull String channel,
                                                    @NonNull HttpServletRequest request) {
        UpdateCatalog catalog = updateService.catalog();
        String requestedAppId = requestedAppId(request);
        String appId = updateService.effectiveAppId(requestedAppId);
        Release release = catalog.resolve(channel);

        if (release == null) {
            // Distinguish a wrong URL (unknown channel) from a transient empty catalog on a real channel.
            if (!catalog.channelPins().containsKey(channel.toLowerCase(Locale.ROOT))) {
                throw new StatusCodeException(ErrorUtil.RESP_404);
            }
            return xml(noUpdateManifest(appId));
        }

        CRXMeta meta = updateService.crxMeta(release.crx());

        if (meta == null) {
            log.warn("[{}] Channel '{}' pins version {} but its CRX {} is missing; serving noupdate",
                    CONTEXT, channel, release.version(), release.crx());
            return xml(noUpdateManifest(appId));
        }

        String codebase = baseUrl(request) + "/updates/download/" + release.crx();
        metricsService.recordUpdateServed(channel.toLowerCase(Locale.ROOT), release.version());
        return xml(updateManifest(appId, release, meta, codebase));
    }

    /**
     * Streams a catalogued CRX. The filename must be well-formed and must belong to a release in the
     * catalog, so this endpoint can never serve an arbitrary file from the updates directory.
     *
     * @param file The CRX filename from the path.
     * @return The CRX bytes, or a 404 when the name is not a catalogued release.
     */
    @GetMapping(value = "/updates/download/{file}")
    public @NonNull ResponseEntity<Resource> download(@PathVariable @NonNull String file) {
        if (!CRX_NAME.matcher(file).matches() || updateService.catalog().byCrx(file) == null) {
            throw new StatusCodeException(ErrorUtil.RESP_404);
        }

        Path path = updateService.crxPath(file);
        CRXMeta meta = updateService.crxMeta(file);

        if (path == null || meta == null) {
            throw new StatusCodeException(ErrorUtil.RESP_404);
        }

        // Version-stamped filenames never change contents, so they are safe to cache for a long time.
        Resource resource = new FileSystemResource(path);
        return ResponseEntity.ok()
                .contentType(CRX_TYPE)
                .contentLength(meta.size())
                .eTag('"' + meta.sha256() + '"')
                .cacheControl(CacheControl.maxAge(Duration.ofDays(365)).cachePublic().immutable())
                .header("Content-Disposition", "attachment; filename=\"" + file + '"')
                .body(resource);
    }

    /**
     * Returns the machine-readable release feed: every packaged build and the version each channel
     * currently resolves to. This is what a change-management process, or the hosted console, subscribes
     * to. Poll it and diff.
     *
     * @param request The incoming request, used to derive a base URL.
     * @return A JSON document describing releases and channels.
     */
    @GetMapping(value = "/updates/releases.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> releasesJson(@NonNull HttpServletRequest request) {
        UpdateCatalog catalog = updateService.catalog();
        String base = baseUrl(request);
        List<Map<String, Object>> releaseItems = new ArrayList<>(catalog.releases().size());

        for (Release release : catalog.releases()) {
            Map<String, Object> item = LinkedHashMap.newLinkedHashMap(9);
            item.put("version", release.version());
            item.put("download", base + "/updates/download/" + release.crx());
            putIfPresent(item, "date", release.date());
            putIfPresent(item, "notes", release.notes());
            putIfPresent(item, "minBrowserVersion", release.minBrowserVersion());
            putIfPresent(item, "rollbackOf", release.rollbackOf());

            CRXMeta meta = updateService.crxMeta(release.crx());

            if (meta == null) {
                item.put("available", false);
            } else {
                item.put("available", true);
                item.put("sha256", meta.sha256());
                item.put("size", meta.size());
            }

            releaseItems.add(item);
        }

        Map<String, Object> channels = LinkedHashMap.newLinkedHashMap(catalog.channelPins().size());

        for (Map.Entry<String, String> entry : catalog.channelPins().entrySet()) {
            Map<String, Object> channel = LinkedHashMap.newLinkedHashMap(4);
            channel.put("pin", entry.getValue());
            Release resolved = catalog.resolve(entry.getKey());

            if (resolved != null) {
                channel.put("version", resolved.version());
                channel.put("download", base + "/updates/download/" + resolved.crx());
                channel.put("manifest", base + "/updates/" + entry.getKey() + ".xml");
            }

            channels.put(entry.getKey(), channel);
        }

        Map<String, Object> body = LinkedHashMap.newLinkedHashMap(3);
        body.put("appId", catalog.appId());
        body.put("channels", channels);
        body.put("releases", releaseItems);
        return json(body);
    }

    /**
     * Returns the release feed as an RSS 2.0 document, so an operator can subscribe to release notices in
     * any feed reader for change management, with one item per packaged build newest first.
     *
     * @param request The incoming request, used to derive a base URL.
     * @return An RSS document.
     */
    @GetMapping("/updates/releases.xml")
    public @NonNull ResponseEntity<String> releasesRss(@NonNull HttpServletRequest request) {
        String base = baseUrl(request);
        StringBuilder sb = new StringBuilder(512);

        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<rss version=\"2.0\"><channel>");
        sb.append("<title>Osprey extension releases</title>");
        sb.append("<link>").append(xmlEscape(base + "/updates/releases.json")).append("</link>");
        sb.append("<description>Packaged Osprey extension builds served by this update server.</description>");

        for (Release release : updateService.catalog().releases()) {
            String download = base + "/updates/download/" + release.crx();
            sb.append("<item>");
            sb.append("<title>Osprey ").append(xmlEscape(release.version())).append("</title>");
            sb.append("<link>").append(xmlEscape(download)).append("</link>");
            sb.append("<guid isPermaLink=\"false\">osprey-").append(xmlEscape(release.version())).append("</guid>");

            String pubDate = rssDate(release.date());

            if (pubDate != null) {
                sb.append("<pubDate>").append(pubDate).append("</pubDate>");
            }

            String description = release.notes() == null ? "" : release.notes();

            if (release.rollbackOf() != null) {
                description = "Rollback of " + release.rollbackOf()
                        + (description.isEmpty() ? "" : (". " + description));
            }

            sb.append("<description>").append(xmlEscape(description)).append("</description>");
            sb.append("</item>");
        }

        sb.append("</channel></rss>");
        return ResponseEntity.ok()
                .contentType(RSS_TYPE)
                .cacheControl(CacheControl.maxAge(Duration.ofSeconds(60)).cachePublic())
                .body(sb.toString());
    }

    /**
     * Returns just the current channel-to-version resolution, a small view convenient for humans and for
     * the hosted console.
     *
     * @param request The incoming request, used to derive a base URL.
     * @return A JSON document mapping each channel to its resolved build.
     */
    @GetMapping(value = "/updates/channels.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public @NonNull ResponseEntity<String> channelsJson(@NonNull HttpServletRequest request) {
        UpdateCatalog catalog = updateService.catalog();
        String base = baseUrl(request);
        Map<String, Object> channels = LinkedHashMap.newLinkedHashMap(catalog.channelPins().size());

        for (Map.Entry<String, String> entry : catalog.channelPins().entrySet()) {
            Map<String, Object> channel = LinkedHashMap.newLinkedHashMap(4);
            channel.put("pin", entry.getValue());
            channel.put("manifest", base + "/updates/" + entry.getKey() + ".xml");
            Release resolved = catalog.resolve(entry.getKey());

            if (resolved != null) {
                channel.put("version", resolved.version());
                channel.put("download", base + "/updates/download/" + resolved.crx());
            }

            channels.put(entry.getKey(), channel);
        }

        Map<String, Object> body = LinkedHashMap.newLinkedHashMap(2);
        body.put("appId", catalog.appId());
        body.put("channels", channels);
        return json(body);
    }

    /**
     * Builds a Chromium update manifest that offers a release.
     *
     * @param appId The application id to echo.
     * @param release The release being offered.
     * @param meta The CRX integrity metadata.
     * @param codebase The absolute CRX download URL.
     * @return The XML document.
     */
    private static @NonNull String updateManifest(@NonNull String appId,
                                                  @NonNull Release release,
                                                  @NonNull CRXMeta meta,
                                                  @NonNull String codebase) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<gupdate xmlns=\"http://www.google.com/update2/response\" protocol=\"2.0\">");
        sb.append("<app appid=\"").append(xmlEscape(appId)).append("\">");
        sb.append("<updatecheck codebase=\"").append(xmlEscape(codebase)).append('"');
        sb.append(" version=\"").append(xmlEscape(release.version())).append('"');
        sb.append(" hash_sha256=\"").append(xmlEscape(meta.sha256())).append('"');
        sb.append(" size=\"").append(meta.size()).append('"');

        if (release.minBrowserVersion() != null && !release.minBrowserVersion().isBlank()) {
            sb.append(" prodversionmin=\"").append(xmlEscape(release.minBrowserVersion())).append('"');
        }

        sb.append(" status=\"ok\"/>");
        sb.append("</app></gupdate>");
        return sb.toString();
    }

    /**
     * Builds a Chromium update manifest that offers no update.
     *
     * @param appId The application id to echo.
     * @return The XML document.
     */
    private static @NonNull String noUpdateManifest(@NonNull String appId) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<gupdate xmlns=\"http://www.google.com/update2/response\" protocol=\"2.0\">"
                + "<app appid=\"" + xmlEscape(appId) + "\">"
                + "<updatecheck status=\"noupdate\"/>"
                + "</app></gupdate>";
    }

    /**
     * Resolves the base origin for absolute URLs: the configured {@code osprey.updates.base-url} when set,
     * otherwise the origin of the incoming request. Configuring it is strongly preferred behind a reverse
     * proxy, where the request the app sees is the internal one.
     *
     * @param request The incoming request.
     * @return The base origin with no trailing slash.
     */
    private @NonNull String baseUrl(@NonNull HttpServletRequest request) {
        String configured = updateService.getBaseUrl();

        if (!configured.isEmpty()) {
            return configured;
        }
        return ServletUriComponentsBuilder.fromContextPath(request).build().toUriString();
    }

    /**
     * Parses the application id a browser presents in its update check. Chromium sends one or more
     * {@code x} parameters shaped like {@code id=<appid>&v=<version>&uc}; the id from the first such
     * parameter is used.
     *
     * @param request The incoming request.
     * @return The requested application id, or {@code null} when none is present.
     */
    private static @Nullable String requestedAppId(@NonNull HttpServletRequest request) {
        String[] values = request.getParameterValues("x");

        if (values == null) {
            return null;
        }

        for (String value : values) {
            for (String part : value.split("&")) {
                if (part.startsWith("id=")) {
                    String id = part.substring(3).strip();

                    if (!id.isEmpty()) {
                        return id;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Formats an authored date as an RFC-1123 date for RSS {@code pubDate}, accepting an offset date-time
     * or a bare date. Returns {@code null} when the value is absent or unparseable, in which case the item
     * simply carries no date.
     *
     * @param date The authored date string, or {@code null}.
     * @return The RFC-1123 date, or {@code null}.
     */
    private static @Nullable String rssDate(@Nullable String date) {
        if (date == null || date.isBlank()) {
            return null;
        }

        String value = date.strip();

        try {
            return DateTimeFormatter.RFC_1123_DATE_TIME.format(OffsetDateTime.parse(value));
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
            // Fall through and try a bare calendar date
        }

        try {
            OffsetDateTime midnight = java.time.LocalDate.parse(value).atStartOfDay().atOffset(ZoneOffset.UTC);
            return DateTimeFormatter.RFC_1123_DATE_TIME.format(midnight);
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception ignored) {
            return null;
        }
    }

    /**
     * Puts a value into the map only when it is non-null and non-blank.
     *
     * @param map The target map.
     * @param key The key.
     * @param value The value, possibly {@code null}.
     */
    private static void putIfPresent(@NonNull Map<String, Object> map, @NonNull String key, @Nullable String value) {
        if (value != null && !value.isBlank()) {
            map.put(key, value);
        }
    }

    /**
     * Escapes text for safe inclusion in an XML attribute or element body.
     *
     * @param value The raw value.
     * @return The escaped value.
     */
    private static @NonNull String xmlEscape(@NonNull String value) {
        StringBuilder sb = new StringBuilder(value.length() + 16);

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&apos;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Wraps an XML document in a response entity with the XML content type and a no-cache directive, since
     * a manifest changes whenever a channel is repinned.
     *
     * @param body The XML body.
     * @return An XML response entity.
     */
    private static @NonNull ResponseEntity<String> xml(@NonNull String body) {
        return ResponseEntity.ok()
                .contentType(XML_UTF8)
                .cacheControl(CacheControl.noCache())
                .body(body);
    }

    /**
     * Serializes a body map to a JSON response, or a 500 on serialization failure.
     *
     * @param body The response body map.
     * @return A JSON response entity.
     */
    private static @NonNull ResponseEntity<String> json(@NonNull Map<String, Object> body) {
        try {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .cacheControl(CacheControl.maxAge(Duration.ofSeconds(60)).cachePublic())
                    .body(JacksonUtil.MAPPER.writeValueAsString(body));
        } catch (@SuppressWarnings("OverlyBroadCatchBlock") Exception e) {
            log.warn("[{}] Failed to serialize response: {}", CONTEXT, e.getClass().getName());
            throw new StatusCodeException(ErrorUtil.RESP_500);
        }
    }
}
