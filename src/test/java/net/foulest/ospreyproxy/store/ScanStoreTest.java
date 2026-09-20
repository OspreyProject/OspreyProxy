/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package net.foulest.ospreyproxy.store;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.lang.reflect.Method;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;

class ScanStoreTest {

    private static final ScanRecord RECORD = new ScanRecord(
            "https://example.com/path", "example.com", "example.com", "malicious",
            Map.of("provider", List.of("malicious")), 1, 1, 10, 20, 1, true, null);

    @Test
    void initializesSchemaAndUsesRetentionConfigurationBranches() {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);

        new ScanStore(jdbc, 0, 4).init();
        new ScanStore(jdbc, -1, 4).pruneScheduled();
        new ScanStore(jdbc, 1, 4).pruneScheduled();

        Mockito.verify(jdbc, Mockito.times(3)).execute(anyString());
        Mockito.verify(jdbc).update(anyString(), anyLong(), eq(4));
    }

    @Test
    void scheduledPruningLogsWhenItDeletesRecords() {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        Mockito.when(jdbc.update(anyString(), anyLong(), eq(4))).thenReturn(1);

        new ScanStore(jdbc, 1, 4).pruneScheduled();

        Mockito.verify(jdbc).update(anyString(), anyLong(), eq(4));
    }

    @Test
    void getReturnsNullForNoRowsAndDatabaseFailure() {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        ScanStore store = new ScanStore(jdbc, 1, 2);

        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq("url"))).thenReturn(List.of());
        Assertions.assertThat(store.get("url")).isNull();
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq("broken"))).thenThrow(new RuntimeException("db"));
        Assertions.assertThat(store.get("broken")).isNull();
    }

    @Test
    void getMapsStoredRecordIncludingNullAndMalformedResults() throws Exception {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        ScanStore store = new ScanStore(jdbc, 1, 2);
        ArgumentCaptor<RowMapper<ScanRecord>> mapper = ArgumentCaptor.forClass(RowMapper.class);
        Mockito.when(jdbc.query(anyString(), mapper.capture(), eq("url"))).thenAnswer(invocation -> {
            ResultSet resultSet = Mockito.mock(ResultSet.class);
            Mockito.when(resultSet.getString("results_json")).thenReturn("{not-json");
            Mockito.when(resultSet.getLong("published_at")).thenReturn(0L);
            Mockito.when(resultSet.wasNull()).thenReturn(true);
            Mockito.when(resultSet.getString(anyString())).thenReturn("value");
            Mockito.when(resultSet.getInt(anyString())).thenReturn(1);
            return List.of(mapper.getValue().mapRow(resultSet, 0));
        });

        ScanRecord mapped = store.get("url");

        Assertions.assertThat(mapped.results()).isEmpty();
        Assertions.assertThat(mapped.publishedAt()).isNull();
    }

    @Test
    void getMapsPublishedRecordAndUpsertsNonIndexableRecords() throws Exception {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        ScanStore store = new ScanStore(jdbc, 1, 2);
        ArgumentCaptor<RowMapper<ScanRecord>> mapper = ArgumentCaptor.forClass(RowMapper.class);
        Mockito.when(jdbc.query(anyString(), mapper.capture(), eq("published"))).thenAnswer(invocation -> {
            ResultSet resultSet = Mockito.mock(ResultSet.class);
            Mockito.when(resultSet.getLong("published_at")).thenReturn(25L);
            Mockito.when(resultSet.wasNull()).thenReturn(false);
            Mockito.when(resultSet.getString(anyString())).thenReturn("value");
            Mockito.when(resultSet.getString("results_json")).thenReturn("{\"provider\":[\"allowed\"]}");
            Mockito.when(resultSet.getInt(anyString())).thenReturn(1);
            return List.of(mapper.getValue().mapRow(resultSet, 0));
        });

        ScanRecord mapped = store.get("published");
        ScanRecord nonIndexable = new ScanRecord(
                RECORD.canonicalUrl(), RECORD.host(), RECORD.bareHost(), RECORD.primaryResult(),
                RECORD.results(), RECORD.flaggedCount(), RECORD.totalCount(), RECORD.firstScannedAt(),
                RECORD.lastScannedAt(), RECORD.scanCount(), false, RECORD.publishedAt());
        store.upsert(nonIndexable);

        Assertions.assertThat(mapped.publishedAt()).isEqualTo(25);
        Assertions.assertThat(mapped.results()).containsEntry("provider", List.of("allowed"));
        Mockito.verify(jdbc).update(anyString(), any(Object[].class));
    }

    @Test
    void getMapsMissingAndBlankStoredResultsToEmptyMaps() {
        for (String json : new String[]{null, ""}) {
            JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
            ScanStore store = new ScanStore(jdbc, 1, 2);
            ArgumentCaptor<RowMapper<ScanRecord>> mapper = ArgumentCaptor.forClass(RowMapper.class);
            Mockito.when(jdbc.query(anyString(), mapper.capture(), eq("url"))).thenAnswer(invocation -> {
                ResultSet resultSet = Mockito.mock(ResultSet.class);
                Mockito.when(resultSet.getString(anyString())).thenReturn("value");
                Mockito.when(resultSet.getString("results_json")).thenReturn(json);
                Mockito.when(resultSet.getInt(anyString())).thenReturn(1);
                Mockito.when(resultSet.getInt("indexable")).thenReturn(0);
                return List.of(mapper.getValue().mapRow(resultSet, 0));
            });

            ScanRecord record = store.get("url");
            Assertions.assertThat(record.results()).isEmpty();
            Assertions.assertThat(record.indexable()).isFalse();
        }
    }

    @Test
    void upsertAndQueriesUseJdbcAndFailSoftly() {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        ScanStore store = new ScanStore(jdbc, 1, 2);

        store.upsert(RECORD);
        Mockito.verify(jdbc).update(anyString(), any(Object[].class));

        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(5))).thenReturn(List.of(RECORD));
        Assertions.assertThat(store.findUnpublished(5)).containsExactly(RECORD);

        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), eq(10L), eq(5))).thenReturn(List.of(RECORD));
        Assertions.assertThat(store.findIndexableSince(10, 5)).containsExactly(RECORD);

        Mockito.when(jdbc.update(anyString(), eq(10L), eq(2))).thenReturn(3);
        Assertions.assertThat(store.pruneStale(10, 2)).isEqualTo(3);

        Mockito.doThrow(new RuntimeException("db")).when(jdbc).batchUpdate(anyString(), anyList());
        store.markPublished(List.of("url"), 20);
        store.markPublished(List.of(), 20);
        Mockito.verify(jdbc, Mockito.times(1)).batchUpdate(anyString(), anyList());
    }

    @Test
    void queryAndUpdateFailuresReturnSafeDefaults() {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        ScanStore store = new ScanStore(jdbc, 1, 2);
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), anyInt())).thenThrow(new RuntimeException("db"));
        Mockito.when(jdbc.query(anyString(), any(RowMapper.class), anyLong(), anyInt())).thenThrow(new RuntimeException("db"));
        Mockito.when(jdbc.update(anyString(), anyLong(), anyInt())).thenThrow(new RuntimeException("db"));
        Mockito.doThrow(new RuntimeException("db")).when(jdbc).update(anyString(), any(Object[].class));

        Assertions.assertThat(store.findUnpublished(1)).isEmpty();
        Assertions.assertThat(store.findIndexableSince(1, 1)).isEmpty();
        Assertions.assertThat(store.pruneStale(1, 1)).isZero();
        Assertions.assertThatCode(() -> store.upsert(RECORD)).doesNotThrowAnyException();
    }

    @Test
    void failsSoftlyWhenPublicationOrSerializationFails() throws Exception {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        Mockito.doThrow(new IllegalStateException("offline")).when(jdbc).batchUpdate(anyString(), anyList());
        new ScanStore(jdbc, 1, 1).markPublished(List.of("url"), 1);

        Method write = ScanStore.class.getDeclaredMethod("writeResults", Map.class);
        write.setAccessible(true);
        Map<String, List<String>> cyclic = new HashMap<>();
        cyclic.put("self", (List) List.of(cyclic));
        Assertions.assertThat(write.invoke(null, cyclic)).isEqualTo("{}");
    }

    @Test
    void marksPublishedRowsInOneBatchAndSkipsEmptyBatches() {
        JdbcTemplate jdbc = Mockito.mock(JdbcTemplate.class);
        ScanStore store = new ScanStore(jdbc, 1, 1);

        store.markPublished(List.of(), 5L);
        Mockito.verify(jdbc, Mockito.never()).batchUpdate(anyString(), anyList());

        store.markPublished(List.of("https://a.example", "https://b.example"), 7L);

        ArgumentCaptor<List<Object[]>> batch = ArgumentCaptor.forClass(List.class);
        Mockito.verify(jdbc).batchUpdate(
                eq("UPDATE scan_result SET published_at = ? WHERE canonical_url = ?"),
                batch.capture());
        Assertions.assertThat(batch.getValue()).hasSize(2);
        Assertions.assertThat(batch.getValue().getFirst()).containsExactly(7L, "https://a.example");
        Assertions.assertThat(batch.getValue().get(1)).containsExactly(7L, "https://b.example");
    }
}
