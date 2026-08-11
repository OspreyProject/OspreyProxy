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
package net.foulest.ospreyproxy.store;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;

/**
 * Wires the durable scan store to a single local SQLite database file.
 * <p>
 * SQLite in WAL mode is used deliberately over a separate database service: the store is small and
 * read-heavy, one file needs no extra process to operate, and a single VPS can back it up by copying
 * a file. A single pooled connection is intentional, since SQLite serializes writers anyway and one
 * connection removes any {@code SQLITE_BUSY} contention for this low write volume.
 * <p>
 * The whole feature is gated on {@code osprey.store.enabled}. When it is off, none of these beans are
 * created and the /check path behaves exactly as it did before the store existed.
 */
@Slf4j
@Configuration
@ConditionalOnProperty(name = "osprey.store.enabled", havingValue = "true")
public class StoreConfig {

    /**
     * Builds the SQLite {@link DataSource} for the scan store.
     *
     * @param path The filesystem path to the SQLite database file.
     * @param busyTimeoutMillis The per-connection busy timeout, in milliseconds.
     * @return A configured SQLite data source.
     */
    @Bean
    public DataSource scanDataSource(@Value("${osprey.store.path:/var/lib/osprey/scans.db}") String path,
                                     @Value("${osprey.store.busy-timeout-millis:5000}") int busyTimeoutMillis) {
        SQLiteConfig config = new SQLiteConfig();
        config.setJournalMode(SQLiteConfig.JournalMode.WAL);
        config.setSynchronous(SQLiteConfig.SynchronousMode.NORMAL);
        config.setBusyTimeout(busyTimeoutMillis);
        config.enforceForeignKeys(true);

        SQLiteDataSource dataSource = new SQLiteDataSource(config);
        dataSource.setUrl("jdbc:sqlite:" + path);
        log.info("[store] Scan store enabled at {}", path);
        return dataSource;
    }

    /**
     * Builds the {@link JdbcTemplate} the store uses for all queries.
     *
     * @param scanDataSource The SQLite data source.
     * @return A JdbcTemplate bound to the scan data source.
     */
    @Bean
    public JdbcTemplate scanJdbcTemplate(@NonNull DataSource scanDataSource) {
        return new JdbcTemplate(scanDataSource);
    }
}
