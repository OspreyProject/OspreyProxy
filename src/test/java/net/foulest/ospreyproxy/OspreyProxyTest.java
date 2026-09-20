package net.foulest.ospreyproxy;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.boot.SpringApplication;

import static org.assertj.core.api.Assertions.assertThat;

class OspreyProxyTest {

    @Test
    void startsSpringApplication() {
        try (MockedStatic<SpringApplication> application = Mockito.mockStatic(SpringApplication.class)) {
            OspreyProxy.main(new String[]{"--spring.main.web-application-type=none"});
            application.verify(() -> SpringApplication.run(OspreyProxy.class,
                    new String[]{"--spring.main.web-application-type=none"}));
        }
    }

    @Test
    void constructsApplicationConfigurationClass() {
        assertThat(new OspreyProxy()).isNotNull();
    }
}
