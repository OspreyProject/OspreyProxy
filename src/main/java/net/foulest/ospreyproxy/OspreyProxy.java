package net.foulest.ospreyproxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.webmvc.autoconfigure.error.ErrorMvcAutoConfiguration;

@SpringBootApplication(exclude = ErrorMvcAutoConfiguration.class)
public class OspreyProxy {

    /**
     * Main method to start the Spring Boot application.
     *
     * @param args - Command-line arguments (not used).
     */
    public static void main(String[] args) {
        SpringApplication.run(OspreyProxy.class, args);
    }
}
