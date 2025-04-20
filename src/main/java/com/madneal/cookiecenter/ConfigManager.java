package com.madneal.cookiecenter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.util.HashMap;
import java.util.Map;

public class ConfigManager {
    private final MontoyaApi api;
    private final Map<String, String> configValues;
    private final PersistedObject settings;

    // Constants for configuration keys
    public static final String API_KEY = "api_key";
    public static final String API_URL = "api_url";
    public static final String ENABLE_FEATURE = "enable_feature";
    public static final String TIMEOUT_MS = "timeout_ms";

    public ConfigManager(MontoyaApi api) {
        this.api = api;
        this.configValues = new HashMap<>();

        // Get the persisted object for our extension
        this.settings = api.persistence().extensionData();

        // Load saved settings
        loadSettings();
    }

    private void loadSettings() {
        // Retrieve settings for each key
        String apiKey = settings.getString(API_KEY);
        String apiUrl = settings.getString(API_URL);
        String enableFeature = settings.getString(ENABLE_FEATURE);
        String timeoutMs = settings.getString(TIMEOUT_MS);

        // Initialize default values if not found
        if (apiKey != null) configValues.put(API_KEY, apiKey);
        if (apiUrl != null) configValues.put(API_URL, apiUrl);
        if (enableFeature != null) configValues.put(ENABLE_FEATURE, enableFeature);
        else configValues.put(ENABLE_FEATURE, "false"); // Default to disabled

        if (timeoutMs != null) configValues.put(TIMEOUT_MS, timeoutMs);
        else configValues.put(TIMEOUT_MS, "5000"); // Default 5 seconds
    }

    public void saveSetting(String key, String value) {
        configValues.put(key, value);
        settings.setString(key, value);
    }

    public String getSetting(String key) {
        return configValues.get(key);
    }

    public boolean getBooleanSetting(String key) {
        String value = configValues.get(key);
        return "true".equalsIgnoreCase(value);
    }

    public int getIntSetting(String key, int defaultValue) {
        String value = configValues.get(key);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}