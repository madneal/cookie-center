package com.madneal.cookiecenter;

public interface CookieCaptureListener {
    void cookieCaptured(String host, String cookieValue);
}
