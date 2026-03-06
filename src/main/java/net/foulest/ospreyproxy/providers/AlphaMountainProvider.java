package net.foulest.ospreyproxy.providers;

import jakarta.annotation.PostConstruct;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class AlphaMountainProvider {

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

    /**
     * Returns the upstream API URL for the provider.
     *
     * @return The AlphaMountainProvider API URL.
     */
    public static @NonNull String getApiUrl() {
        return API_URL;
    }

    /**
     * Builds the request body for the API.
     *
     * @param url - The URL to check.
     * @return The request body map expected by the API.
     */
    public static @NonNull Map<String, Object> buildBody(@NonNull String url) {
        Map<String, Object> body = new HashMap<>();
        body.put("uri", url);
        body.put("license", API_KEY);
        body.put("version", 1);
        body.put("type", "partner.info");
        return body;
    }
}
