/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.updates;

import jakarta.servlet.http.HttpServletRequest;
import net.foulest.ospreyproxy.exceptions.StatusCodeException;
import net.foulest.ospreyproxy.services.MetricsService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

class UpdateHandlerTest {

    private static final Release RELEASE = new Release("2.0.0", "osprey-2.crx",
            "2026-02-03", "notes & more", null, "120", null);
    private static final CRXMeta META = new CRXMeta("a".repeat(64), 42, 1);

    @Test
    void manifestDistinguishesUnknownKnownEmptyAndMissingCrxChannels() {
        UpdateService service = Mockito.mock(UpdateService.class);
        MetricsService metrics = Mockito.mock(MetricsService.class);
        UpdateHandler handler = new UpdateHandler(service, metrics);
        HttpServletRequest request = request();
        Mockito.when(service.effectiveAppId(any())).thenReturn("app");

        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(), Map.of("stable", "latest")));
        Assertions.assertThat(handler.manifest("stable", request).getBody()).contains("status=\"noupdate\"");
        Assertions.assertThatThrownBy(() -> handler.manifest("wrong", request))
                .isInstanceOf(StatusCodeException.class);

        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(RELEASE), Map.of("stable", "latest")));
        Mockito.when(service.crxMeta(RELEASE.crx())).thenReturn(null);
        Assertions.assertThat(handler.manifest("stable", request).getBody()).contains("status=\"noupdate\"");
        Mockito.verify(metrics, Mockito.never()).recordUpdateServed(anyString(), anyString());
    }

    @Test
    void manifestBuildsEscapedOfferAndUsesFirstRequestedAppId() {
        UpdateService service = Mockito.mock(UpdateService.class);
        MetricsService metrics = Mockito.mock(MetricsService.class);
        UpdateHandler handler = new UpdateHandler(service, metrics);
        HttpServletRequest request = request();
        Mockito.when(request.getParameterValues("x")).thenReturn(new String[]{"v=1&uc", "id= requested<& &v=2"});
        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("ignored", List.of(RELEASE), Map.of("stable", "latest")));
        Mockito.when(service.effectiveAppId("requested<")).thenReturn("app<&");
        Mockito.when(service.crxMeta(RELEASE.crx())).thenReturn(META);
        Mockito.when(service.getBaseUrl()).thenReturn("https://updates.example");

        ResponseEntity<String> response = handler.manifest("STABLE", request);

        Assertions.assertThat(response.getBody())
                .contains("appid=\"app&lt;&amp;\"")
                .contains("codebase=\"https://updates.example/updates/download/osprey-2.crx\"")
                .contains("prodversionmin=\"120\"")
                .contains("hash_sha256=\"" + "a".repeat(64) + "\"");
        Mockito.verify(metrics).recordUpdateServed("stable", "2.0.0");
    }

    @Test
    void downloadRejectsBadOrUncataloguedAndServesOnlyAvailableCataloguedCrx() {
        UpdateService service = Mockito.mock(UpdateService.class);
        UpdateHandler handler = new UpdateHandler(service, Mockito.mock(MetricsService.class));
        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(RELEASE), Map.of()));

        Assertions.assertThatThrownBy(() -> handler.download("../secret.crx")).isInstanceOf(StatusCodeException.class);
        Assertions.assertThatThrownBy(() -> handler.download("missing.crx")).isInstanceOf(StatusCodeException.class);

        Mockito.when(service.crxPath(RELEASE.crx())).thenReturn(null);
        Mockito.when(service.crxMeta(RELEASE.crx())).thenReturn(META);
        Assertions.assertThatThrownBy(() -> handler.download(RELEASE.crx())).isInstanceOf(StatusCodeException.class);

        Mockito.when(service.crxPath(RELEASE.crx())).thenReturn(Path.of("package.crx"));
        ResponseEntity<Resource> response = handler.download(RELEASE.crx());
        Assertions.assertThat(response.getHeaders().getContentLength()).isEqualTo(42);
        Assertions.assertThat(response.getHeaders().getETag()).isEqualTo("\"" + "a".repeat(64) + "\"");
        Assertions.assertThat(response.getHeaders().getFirst("Content-Disposition"))
                .isEqualTo("attachment; filename=\"osprey-2.crx\"");

        Mockito.when(service.crxMeta(RELEASE.crx())).thenReturn(null);
        Assertions.assertThatThrownBy(() -> handler.download(RELEASE.crx())).isInstanceOf(StatusCodeException.class);
    }

    @Test
    void jsonFeedsShowAvailableAndUnavailableReleasesAndResolvedChannels() {
        Release unavailable = new Release("1.0.0", "old.crx", null, null, null, null, null);
        UpdateCatalog catalog = new UpdateCatalog("app", List.of(RELEASE, unavailable),
                Map.of("stable", "latest", "missing", "9.0.0"));
        UpdateService service = Mockito.mock(UpdateService.class);
        Mockito.when(service.catalog()).thenReturn(catalog);
        Mockito.when(service.getBaseUrl()).thenReturn("https://updates.example");
        Mockito.when(service.crxMeta(RELEASE.crx())).thenReturn(META);
        Mockito.when(service.crxMeta(unavailable.crx())).thenReturn(null);
        UpdateHandler handler = new UpdateHandler(service, Mockito.mock(MetricsService.class));

        String releases = handler.releasesJson(request()).getBody();
        String channels = handler.channelsJson(request()).getBody();

        Assertions.assertThat(releases)
                .contains("\"available\":true", "\"available\":false", "\"sha256\":\"" + "a".repeat(64) + "\"")
                .contains("https://updates.example/updates/download/osprey-2.crx");
        Assertions.assertThat(channels)
                .contains("\"stable\"", "\"version\":\"2.0.0\"", "\"missing\"", "\"pin\":\"9.0.0\"");
    }

    @Test
    void rssEscapesContentAndHandlesOffsetBareInvalidAndMissingDates() {
        Release offset = new Release("3.0.0", "three.crx", "2026-01-02T03:04:05+01:00",
                "x < y", null, null, "2.0.0");
        Release invalid = new Release("2.0.0", "two.crx", "not-a-date", null, null, null, null);
        Release blank = new Release("1.0.0", "one.crx", " ", null, null, null, null);
        UpdateService service = Mockito.mock(UpdateService.class);
        Mockito.when(service.getBaseUrl()).thenReturn("https://updates.example");
        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(offset, invalid, blank), Map.of()));
        UpdateHandler handler = new UpdateHandler(service, Mockito.mock(MetricsService.class));

        String body = handler.releasesRss(request()).getBody();

        Assertions.assertThat(body)
                .contains("<pubDate>")
                .contains("Rollback of 2.0.0. x &lt; y")
                .contains("<guid isPermaLink=\"false\">osprey-3.0.0</guid>")
                .doesNotContain("not-a-date");
    }

    @Test
    void derivesRequestOriginAndCoversEmptyOptionalReleaseValues() {
        Release escaped = new Release("2.0.0", "quoted.crx", null, " ", null, " ", null);
        Release rollback = new Release("1.0.0", "rollback.crx", null, null, null, null, "0.9.0");
        UpdateService service = Mockito.mock(UpdateService.class);
        Mockito.when(service.getBaseUrl()).thenReturn("");
        Mockito.when(service.effectiveAppId(any())).thenAnswer(invocation -> invocation.getArgument(0));
        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(escaped, rollback),
                Map.of("stable", "latest")));
        Mockito.when(service.crxMeta(escaped.crx())).thenReturn(META);
        UpdateHandler handler = new UpdateHandler(service, Mockito.mock(MetricsService.class));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/updates/stable.xml");
        request.setScheme("https");
        request.setServerName("proxy.example");
        request.setServerPort(443);
        request.setParameter("x", "v=1", "id=   &v=2", "id=app'\">&<&v=3");

        String manifest = handler.manifest("stable", request).getBody();
        String releases = handler.releasesJson(request).getBody();
        String rss = handler.releasesRss(request).getBody();

        Assertions.assertThat(manifest)
                .contains("appid=\"app&apos;&quot;&gt;\"")
                .contains("codebase=\"https://proxy.example/updates/download/quoted.crx\"")
                .doesNotContain("prodversionmin");
        Assertions.assertThat(releases)
                .doesNotContain("\"date\"", "\"notes\"", "\"minBrowserVersion\"")
                .contains("\"rollbackOf\":\"0.9.0\"");
        Assertions.assertThat(rss).contains("Rollback of 0.9.0</description>");
    }

    @Test
    void omitsMinimumBrowserVersionWhenItIsAbsent() {
        Release withoutMinimum = new Release("1.0.0", "minimal.crx", null, null, null, null, null);
        UpdateService service = Mockito.mock(UpdateService.class);
        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(withoutMinimum),
                Map.of("stable", "latest")));
        Mockito.when(service.effectiveAppId(null)).thenReturn("app");
        Mockito.when(service.crxMeta(withoutMinimum.crx())).thenReturn(META);
        Mockito.when(service.getBaseUrl()).thenReturn("https://updates.example");
        UpdateHandler handler = new UpdateHandler(service, Mockito.mock(MetricsService.class));

        String manifest = handler.manifest("stable", request()).getBody();

        Assertions.assertThat(manifest).doesNotContain("prodversionmin");
    }

    @Test
    void manifestHandlesAnEmptyUpdateCheckParameterArray() {
        UpdateService service = Mockito.mock(UpdateService.class);
        Mockito.when(service.catalog()).thenReturn(new UpdateCatalog("app", List.of(RELEASE), Map.of("stable", "latest")));
        Mockito.when(service.effectiveAppId(null)).thenReturn("app");
        Mockito.when(service.crxMeta(RELEASE.crx())).thenReturn(META);
        Mockito.when(service.getBaseUrl()).thenReturn("https://updates.example");
        HttpServletRequest request = request();
        Mockito.when(request.getParameterValues("x")).thenReturn(new String[0]);

        new UpdateHandler(service, Mockito.mock(MetricsService.class)).manifest("stable", request);

        Mockito.verify(service).effectiveAppId(null);
    }

    @Test
    void formatsBareRssDatesAndFallsBackWhenJsonCannotSerialize() throws Exception {
        Method rssDate = UpdateHandler.class.getDeclaredMethod("rssDate", String.class);
        rssDate.setAccessible(true);
        Assertions.assertThat(rssDate.invoke(null, "2026-01-02").toString()).contains("Fri, 2 Jan 2026");

        Method json = UpdateHandler.class.getDeclaredMethod("json", Map.class);
        json.setAccessible(true);
        Map<String, Object> cyclic = new HashMap<>();
        cyclic.put("self", cyclic);
        Assertions.assertThatThrownBy(() -> json.invoke(null, cyclic))
                .isInstanceOf(InvocationTargetException.class)
                .hasCauseInstanceOf(StatusCodeException.class);
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getParameterValues("x")).thenReturn(null);
        return request;
    }
}
