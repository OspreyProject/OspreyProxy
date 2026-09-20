package net.foulest.ospreyproxy.util;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.crypto.Mac;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HashUtilTest {

    @Test
    void hashesIpAndUrlsWithSeparateStableHmacs() {
        assertThat(HashUtil.hashIp("192.0.2.1")).hasSize(64).isEqualTo(HashUtil.hashIp("192.0.2.1"));
        assertThat(HashUtil.hashUrl("https://example.com")).hasSize(64)
                .isNotEqualTo(HashUtil.hashIp("https://example.com"));
    }

    @Test
    void createsFreshMacWhenPrototypeCannotBeCloned() throws Exception {
        Mac prototype = Mockito.mock(Mac.class);
        Mockito.when(prototype.clone()).thenThrow(new CloneNotSupportedException());
        Method newMac = HashUtil.class.getDeclaredMethod("newMac", Mac.class, byte[].class);
        newMac.setAccessible(true);

        Mac result = (Mac) newMac.invoke(null, prototype, new byte[32]);

        assertThat(result.getAlgorithm()).isEqualTo("HmacSHA256");
    }

    @Test
    void reportsUnavailableHmacAlgorithm() throws Exception {
        HashUtil.hashUrl("https://example.com");
        Method createMac = HashUtil.class.getDeclaredMethod("createMac", byte[].class);
        createMac.setAccessible(true);
        try (MockedStatic<Mac> macs = Mockito.mockStatic(Mac.class)) {
            macs.when(() -> Mac.getInstance("HmacSHA256"))
                    .thenThrow(new java.security.NoSuchAlgorithmException("missing"));
            assertThatThrownBy(() -> createMac.invoke(null, new byte[32]))
                    .hasCauseInstanceOf(IllegalStateException.class);
        }
    }
}
