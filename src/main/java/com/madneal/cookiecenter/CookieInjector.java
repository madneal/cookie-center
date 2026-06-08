package com.madneal.cookiecenter;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

public class CookieInjector implements HttpHandler {
    private final CookieCenter cookieCenter;
    private final CookieCaptureListener captureListener;
    private volatile boolean autoCaptureEnabled;

    public CookieInjector(CookieCenter cookieCenter, CookieCaptureListener captureListener) {
        this.cookieCenter = cookieCenter;
        this.captureListener = captureListener;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        captureProxyCookie(requestToBeSent);

        CookieEntry matchingEntry = cookieCenter.findMatchingCookie(requestToBeSent.httpService().host());
        if (matchingEntry == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        HttpRequest modifiedRequest = updateCookieHeader(requestToBeSent, matchingEntry.getCookieValue());

        return RequestToBeSentAction.continueWith(modifiedRequest);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private HttpRequest updateCookieHeader(HttpRequestToBeSent request, String cookieValue) {
        String currentCookieHeader = request.headerValue("Cookie");

        if (currentCookieHeader != null && !currentCookieHeader.isEmpty()) {
            return request.withUpdatedHeader("Cookie", cookieValue);
        }

        return request.withAddedHeader("Cookie", cookieValue);
    }

    public void setAutoCaptureEnabled(boolean autoCaptureEnabled) {
        this.autoCaptureEnabled = autoCaptureEnabled;
    }

    private void captureProxyCookie(HttpRequestToBeSent request) {
        if (!autoCaptureEnabled || captureListener == null || !request.toolSource().isFromTool(ToolType.PROXY)) {
            return;
        }

        String cookieValue = request.headerValue("Cookie");
        if (cookieValue == null || cookieValue.trim().isEmpty()) {
            return;
        }

        captureListener.cookieCaptured(request.httpService().host(), cookieValue);
    }
}
