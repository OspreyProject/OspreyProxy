package net.foulest.ospreyproxy.store;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StoreConfigTest {

    @Test
    void configuresSqliteDataSourceAndJdbcTemplate() throws Exception {
        StoreConfig config = new StoreConfig();
        javax.sql.DataSource dataSource = config.scanDataSource(":memory:", 1234);

        try (var connection = dataSource.getConnection()) {
            assertThat(connection.getMetaData().getURL()).isEqualTo("jdbc:sqlite::memory:");
        }
        assertThat(config.scanJdbcTemplate(dataSource).getDataSource()).isSameAs(dataSource);
    }
}
