package com.madneal.cookiecenter;

public class CookieEntry {
    private String host;
    private String cookieValue;
    private boolean enabled;
    private boolean includeSubdomains;

    public CookieEntry(String host, String cookieValue) {
        this(host, cookieValue, true, true);
    }

    public CookieEntry(String host, String cookieValue, boolean enabled, boolean includeSubdomains) {
        this.host = host;
        this.cookieValue = cookieValue;
        this.enabled = enabled;
        this.includeSubdomains = includeSubdomains;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getCookieValue() {
        return cookieValue;
    }

    public void setCookieValue(String cookieValue) {
        this.cookieValue = cookieValue;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isIncludeSubdomains() {
        return includeSubdomains;
    }

    public void setIncludeSubdomains(boolean includeSubdomains) {
        this.includeSubdomains = includeSubdomains;
    }
}
