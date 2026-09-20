/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.services;

import net.foulest.ospreyproxy.store.ScanRecord;
import net.foulest.ospreyproxy.store.ScanStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;

class IndexingServiceTest {

    private static final ScanRecord RECORD = new ScanRecord(
            "https://example.com/path", "example.com", "example.com", "malicious",
            Map.of(), 1, 1, 1, 1, 1, true, null);

    @AfterEach
    void clearInterruptedStatus() {
        Thread.interrupted();
    }

    @Test
    void skipsWhenKeyIsBlankOrNoRecordsArePending() {
        ScanStore store = Mockito.mock(ScanStore.class);
        new IndexingService(store, "", "", "https://index.invalid", "", 10, 1).publish();
        Mockito.verifyNoInteractions(store);

        Mockito.when(store.findUnpublished(10)).thenReturn(List.of());
        new IndexingService(store, "key", "", "https://index.invalid", "", 10, 1).publish();
        Mockito.verify(store).findUnpublished(10);
        Mockito.verify(store, Mockito.never()).markPublished(anyList(), anyLong());
    }

    @Test
    void testingHostLeavesOtherRecordsUnpublished() {
        ScanStore store = Mockito.mock(ScanStore.class);
        Mockito.when(store.findUnpublished(10)).thenReturn(List.of(RECORD));

        new IndexingService(store, "key", "", "https://index.invalid", "other.example", 10, 1).publish();

        Mockito.verify(store).findUnpublished(10);
        Mockito.verify(store, Mockito.never()).markPublished(anyList(), anyLong());
    }

    @Test
    void acceptedSubmissionMarksExactlySubmittedCanonicalUrls() throws Exception {
        ScanStore store = Mockito.mock(ScanStore.class);
        Mockito.when(store.findUnpublished(10)).thenReturn(List.of(RECORD));
        IndexingService service = new IndexingService(store, "key", "", "https://index.invalid", "EXAMPLE.COM", 10, 1);
        HttpClient client = mockClientWithStatus(200);
        setClient(service, client);

        service.publish();

        ArgumentCaptor<List<String>> urls = ArgumentCaptor.forClass(List.class);
        Mockito.verify(store).markPublished(urls.capture(), anyLong());
        assertThat(urls.getValue()).containsExactly(RECORD.canonicalUrl());
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        Mockito.verify(client).send(request.capture(), any(HttpResponse.BodyHandler.class));
        assertThat(request.getValue().uri()).hasToString("https://index.invalid");
        assertThat(request.getValue().headers().firstValue("Content-Type")).contains("application/json; charset=utf-8");
    }

    @Test
    void queuedSubmissionIsAcceptedButErrorAndInterruptedRequestsAreNot() throws Exception {
        ScanStore queuedStore = Mockito.mock(ScanStore.class);
        Mockito.when(queuedStore.findUnpublished(10)).thenReturn(List.of(RECORD));
        IndexingService queued = new IndexingService(queuedStore, "key", "https://key.example/key.txt",
                "https://index.invalid", "", 10, 1);
        setClient(queued, mockClientWithStatus(202));
        queued.publish();
        Mockito.verify(queuedStore).markPublished(anyList(), anyLong());

        ScanStore rejectedStore = Mockito.mock(ScanStore.class);
        Mockito.when(rejectedStore.findUnpublished(10)).thenReturn(List.of(RECORD));
        IndexingService rejected = new IndexingService(rejectedStore, "key", "", "https://index.invalid", "", 10, 1);
        setClient(rejected, mockClientWithStatus(500));
        rejected.publish();
        Mockito.verify(rejectedStore, Mockito.never()).markPublished(anyList(), anyLong());

        ScanStore interruptedStore = Mockito.mock(ScanStore.class);
        Mockito.when(interruptedStore.findUnpublished(10)).thenReturn(List.of(RECORD));
        IndexingService interrupted = new IndexingService(interruptedStore, "key", "", "https://index.invalid", "", 10, 1);
        HttpClient interruptedClient = Mockito.mock(HttpClient.class);
        Mockito.when(interruptedClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("stop"));
        setClient(interrupted, interruptedClient);
        interrupted.publish();
        Mockito.verify(interruptedStore, Mockito.never()).markPublished(anyList(), anyLong());
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
    }

    @Test
    void preservesRecordsWhenSubmittingToIndexNowFails() throws Exception {
        ScanStore store = Mockito.mock(ScanStore.class);
        ScanRecord record = new ScanRecord("https://example.com", "example.com", "example.com",
                "malicious", Map.of(), 1, 1, 1, 1, 1, true, null);
        Mockito.when(store.findUnpublished(10)).thenReturn(List.of(record));
        IndexingService service = new IndexingService(store, "key", "", "https://index.example", "", 10, 1);
        HttpClient client = Mockito.mock(HttpClient.class);
        Mockito.when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("offline"));
        ReflectionTestUtils.setField(service, "client", client);

        service.publish();

        Mockito.verify(store, Mockito.never()).markPublished(anyList(), anyLong());
    }

    @SuppressWarnings("unchecked")
    private static HttpClient mockClientWithStatus(int status) throws Exception {
        HttpClient client = Mockito.mock(HttpClient.class);
        HttpResponse<Void> response = Mockito.mock(HttpResponse.class);
        Mockito.when(response.statusCode()).thenReturn(status);
        Mockito.when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(response);
        return client;
    }

    private static void setClient(IndexingService service, HttpClient client) throws Exception {
        Field field = IndexingService.class.getDeclaredField("client");
        field.setAccessible(true);
        field.set(service, client);
    }
}
