package com.madneal.cookiecenter;

import burp.IBurpExtenderCallbacks;

import java.util.HashMap;
import java.util.Map;

public class ConfigManager {
    private final IBurpExtenderCallbacks callbacks;
    private final Map<String, String> configValues;

    // Constants for configuration keys
    public static final String API_KEY = "api_key";
    public static final String API_URL = "api_url";
    public static final String ENABLE_FEATURE = "enable_feature";
    public static final String TIMEOUT_MS = "timeout_ms";

    public ConfigManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.configValues = new HashMap<>();

        // Load saved settings from Burp's persistent storage
        loadSettings();
    }

    // Load settings from Burp's persistent storage
    private void loadSettings() {
        // Retrieve settings for each key
        String apiKey = callbacks.loadExtensionSetting(API_KEY);
        String apiUrl = callbacks.loadExtensionSetting(API_URL);
        String enableFeature = callbacks.loadExtensionSetting(ENABLE_FEATURE);
        String timeoutMs = callbacks.loadExtensionSetting(TIMEOUT_MS);

        // Initialize default values if not found
        if (apiKey != null) configValues.put(API_KEY, apiKey);
        if (apiUrl != null) configValues.put(API_URL, apiUrl);
        if (enableFeature != null) configValues.put(ENABLE_FEATURE, enableFeature);
        else configValues.put(ENABLE_FEATURE, "false"); // Default to disabled

        if (timeoutMs != null) configValues.put(TIMEOUT_MS, timeoutMs);
        else configValues.put(TIMEOUT_MS, "5000"); // Default 5 seconds
    }

    // Save a specific setting
    public void saveSetting(String key, String value) {
        configValues.put(key, value);
        callbacks.saveExtensionSetting(key, value);
    }

    // Get a specific setting
    public String getSetting(String key) {
        return configValues.get(key);
    }

    // Get boolean setting
    public boolean getBooleanSetting(String key) {
        String value = configValues.get(key);
        return "true".equalsIgnoreCase(value);
    }

    // Get integer setting
    public int getIntSetting(String key, int defaultValue) {
        String value = configValues.get(key);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}