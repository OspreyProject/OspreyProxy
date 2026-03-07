package net.foulest.ospreyproxy.providers;

import jakarta.annotation.PostConstruct;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class PrecisionSecProvider implements Provider {

    // API key and URL
    private static final String API_KEY = System.getenv("PRECISIONSEC_API_KEY");
    private static final String API_URL = "https://api.precisionsec.com/check_url/";

    @PostConstruct
    public void validateConfig() {
        if (API_KEY == null || API_KEY.isBlank()) {
            throw new IllegalStateException("PRECISIONSEC_API_KEY environment variable is not set");
        }

        // Enforce HTTPS to prevent API key exposure in cleartext
        // noinspection ConstantValue
        if (!API_URL.startsWith("https://")) {
            throw new IllegalStateException("PrecisionSec API URL must use HTTPS");
        }
    }

    @Override
    public @NotNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NotNull String getMethod() {
        return "GET";
    }

    @Override
    public @NotNull Map<String, String> getHeaders() {
        return Map.of("API-Key", API_KEY);
    }

    @Override
    public @NotNull String buildRequestUrl(@NotNull String url) {
        String encoded = URLEncoder.encode(url, StandardCharsets.UTF_8);
        return API_URL + encoded;
    }
}
