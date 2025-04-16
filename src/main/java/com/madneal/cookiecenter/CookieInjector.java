package com.madneal.cookiecenter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

public class CookieInjector implements HttpHandler {
    private final CookieTableModel cookieTableModel;
    private final MontoyaApi api;

    public CookieInjector(CookieTableModel cookieTableModel, MontoyaApi api) {
        this.cookieTableModel = cookieTableModel;
        this.api = api;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // We don't need to modify responses
        return ResponseReceivedAction.continueWith(responseReceived);
    }



    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        String requestHost = requestToBeSent.httpService().host();
        CookieEntry matchingEntry = findMatchingCookieEntry(requestHost);

        if (matchingEntry != null) {
            String cookieValue = matchingEntry.getCookieValue();
            api.logging().logToOutput("Added new cookie: " + cookieValue);
            HttpRequest modifiedRequest = requestToBeSent.withRemovedHeader("Cookie")
                    .withAddedHeader("Cookie", cookieValue);
            api.logging().logToOutput("Final modified request: " + modifiedRequest);
            duplicateWithCookie(modifiedRequest);
            return RequestToBeSentAction.continueWith(modifiedRequest);
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    private void duplicateWithCookie(HttpRequest request) {
        api.repeater().sendToRepeater(request);
    }

    private CookieEntry findMatchingCookieEntry(String host) {
        api.logging().logToOutput("Find matching cookie entry for host: " + host);
        List<CookieEntry> entries = cookieTableModel.getEntries();
        api.logging().logToOutput("Found " + entries.size() + " cookies");

        // First try exact match
        for (CookieEntry entry : entries) {
            if (host.equalsIgnoreCase(entry.getHost())) {
                api.logging().logToOutput("Found matching cookie entry for host: " + entry.getCookieValue());
                return entry;
            }
        }

        // Then try domain match (example.com should match sub.example.com)
        for (CookieEntry entry : entries) {
            String entryHost = entry.getHost();
            if (host.toLowerCase().endsWith("." + entryHost.toLowerCase())) {
                return entry;
            }
        }

        return null;
    }

    private HttpRequest updateCookieHeader(HttpRequestToBeSent request, String cookieValue) {
        if (cookieValue == null || cookieValue.isEmpty()) {
            api.logging().logToOutput("Empty cookie value, not modifying request");
            return request;
        }

        // Check if the request already has a Cookie header
        String currentCookieHeader = request.headerValue("Cookie");
        HttpRequest updatedRequest;

        if (currentCookieHeader != null && !currentCookieHeader.isEmpty()) {
            // Replace existing Cookie header
            api.logging().logToOutput("Replacing cookie header: " + currentCookieHeader + " -> " + cookieValue);
            updatedRequest = request.withUpdatedHeader("Cookie", cookieValue);
        } else {
            // Add new Cookie header
            api.logging().logToOutput("Adding new cookie header: " + cookieValue);
            updatedRequest = request.withAddedHeader("Cookie", cookieValue);
        }

        return updatedRequest;
    }
}
