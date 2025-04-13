package com.madneal.cookiecenter;

public class CookieEntry {
    private String host;
    private String cookieValue;

    public CookieEntry(String host, String cookieValue) {
        this.host = host;
        this.cookieValue = cookieValue;
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
}
