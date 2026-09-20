package net.foulest.ospreyproxy.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class APIKeyUtilTest {

    @Test
    void orEmptyReturnsKeyWhenNonNull() {
        Assertions.assertThat(APIKeyUtil.orEmpty("my-key")).isEqualTo("my-key");
    }

    @Test
    void orEmptyReturnsEmptyStringWhenNull() {
        Assertions.assertThat(APIKeyUtil.orEmpty(null)).isEmpty();
    }

    @Test
    void requireNonBlankThrowsWhenKeyIsNull() {
        Assertions.assertThatThrownBy(() -> APIKeyUtil.requireNonBlank(null, "missing"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("missing");
    }

    @Test
    void requireNonBlankThrowsWhenKeyIsBlank() {
        Assertions.assertThatThrownBy(() -> APIKeyUtil.requireNonBlank(" ", "blank"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("blank");
    }

    @Test
    void requireNonBlankDoesNotThrowWhenKeyIsPresent() {
        Assertions.assertThatCode(() -> APIKeyUtil.requireNonBlank("real-key", "unused"))
                .doesNotThrowAnyException();
    }
}
