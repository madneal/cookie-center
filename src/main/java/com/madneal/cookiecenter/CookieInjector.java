package com.madneal.cookiecenter;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

public class CookieInjector implements HttpHandler {
    private final CookieCenter cookieCenter;

    public CookieInjector(CookieCenter cookieCenter) {
        this.cookieCenter = cookieCenter;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
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
}
