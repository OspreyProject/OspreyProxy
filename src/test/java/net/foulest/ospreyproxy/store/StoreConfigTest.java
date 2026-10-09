package net.foulest.ospreyproxy.store;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StoreConfigTest {

    @Test
    void configuresSqliteDataSourceAndJdbcTemplate() throws Exception {
        StoreConfig config = new StoreConfig();
        javax.sql.DataSource dataSource = config.scanDataSource(":memory:", 1234);

        try (var closeable = (com.zaxxer.hikari.HikariDataSource) dataSource) {
            try (var connection = dataSource.getConnection()) {
                assertThat(connection.getMetaData().getURL()).isEqualTo("jdbc:sqlite::memory:");
            }
            assertThat(config.scanJdbcTemplate(dataSource).getDataSource()).isSameAs(dataSource);
            assertThat(closeable.getMaximumPoolSize()).isEqualTo(1);
        }
    }

    @Test
    void poolsASingleConnectionSoTheInMemoryDatabaseIsSharedAcrossCalls() throws Exception {
        StoreConfig config = new StoreConfig();

        try (var dataSource = (com.zaxxer.hikari.HikariDataSource) config.scanDataSource(":memory:", 1000)) {
            var jdbc = config.scanJdbcTemplate(dataSource);
            jdbc.execute("CREATE TABLE t (id INTEGER)");
            jdbc.update("INSERT INTO t VALUES (1)");

            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM t", Integer.class)).isEqualTo(1);
        }
    }
}
