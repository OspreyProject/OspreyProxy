package net.foulest.ospreyproxy.providers;

import jakarta.annotation.PostConstruct;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class AlphaMountainProvider implements Provider {

    // API key and URL
    private static final String API_KEY = System.getenv("ALPHAMOUNTAIN_API_KEY");
    private static final String API_URL = "https://api.alphamountain.ai/category/uri";

    @PostConstruct
    public void validateConfig() {
        if (API_KEY == null || API_KEY.isBlank()) {
            throw new IllegalStateException("ALPHAMOUNTAIN_API_KEY environment variable is not set");
        }

        // Enforce HTTPS to prevent API key exposure in cleartext
        // noinspection ConstantValue
        if (!API_URL.startsWith("https://")) {
            throw new IllegalStateException("AlphaMountain API URL must use HTTPS");
        }
    }

    @Override
    public @NotNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NotNull Map<String, Object> buildBody(@NotNull String url) {
        Map<String, Object> body = new HashMap<>();
        body.put("uri", url);
        body.put("license", API_KEY);
        body.put("version", 1);
        body.put("type", "partner.info");
        return body;
    }
}
