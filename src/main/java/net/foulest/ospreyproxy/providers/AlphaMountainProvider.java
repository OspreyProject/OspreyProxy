package net.foulest.ospreyproxy.providers;

import jakarta.annotation.PostConstruct;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class AlphaMountainProvider implements Provider {

    // API key and URL
    private static final String API_KEY = System.getenv("ALPHAMOUNTAIN_API_KEY");
    private static final String API_URL = "https://api.alphamountain.ai/category/uri";

    // Static fields for request body parameters
    private static final String LICENSE = API_KEY;
    private static final int VERSION = 1;
    private static final String TYPE = "partner.info";

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
    public @NonNull String getApiUrl() {
        return API_URL;
    }

    @Override
    public @NonNull Map<String, Object> buildBody(@NonNull String url) {
        return Map.of(
                "uri", url,
                "license", LICENSE,
                "version", VERSION,
                "type", TYPE
        );
    }
}
