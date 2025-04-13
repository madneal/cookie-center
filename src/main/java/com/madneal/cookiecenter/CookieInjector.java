package com.madneal.cookiecenter;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

public class CookieInjector implements HttpHandler {
    private final CookieTableModel cookieTableModel;

    public CookieInjector(CookieTableModel cookieTableModel) {
        this.cookieTableModel = cookieTableModel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Get the host from the request
        String requestHost = requestToBeSent.httpService().host();

        // Check if we have cookies for this host
        CookieEntry matchingEntry = findMatchingCookieEntry(requestHost);
        if (matchingEntry == null) {
            // No matching cookies, continue with unmodified request
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Create a new request with the cookie header
        HttpRequest modifiedRequest = updateCookieHeader(requestToBeSent, matchingEntry.getCookieValue());

        // Continue with the modified request
        return RequestToBeSentAction.continueWith(modifiedRequest);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // We don't need to modify responses
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private CookieEntry findMatchingCookieEntry(String host) {
        List<CookieEntry> entries = cookieTableModel.getEntries();
        for (CookieEntry entry : entries) {
            // Match entire domain or subdomain pattern
            if (host.equals(entry.getHost()) || host.endsWith("." + entry.getHost())) {
                return entry;
            }
        }
        return null;
    }

    private HttpRequest updateCookieHeader(HttpRequestToBeSent request, String cookieValue) {
        // Check if the request already has a Cookie header
        String currentCookieHeader = request.headerValue("Cookie");

        if (currentCookieHeader != null && !currentCookieHeader.isEmpty()) {
            // Replace existing Cookie header
            return request.withUpdatedHeader("Cookie", cookieValue);
        } else {
            // Add new Cookie header
            return request.withAddedHeader("Cookie", cookieValue);
        }
    }
}
