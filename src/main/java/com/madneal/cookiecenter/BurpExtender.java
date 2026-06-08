package com.madneal.cookiecenter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private ConfigPanel configPanel;
    private CookieCenter cookieCenter;
    private CookieTableModel cookieTableModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("Cookie Center");
        api.logging().logToOutput("Extension loading...");

        cookieCenter = new CookieCenter();
        cookieTableModel = new CookieTableModel(cookieCenter);
        CookieInjector cookieInjector = new CookieInjector(cookieCenter, (host, cookieValue) ->
                configPanel.cookieCaptured(host, cookieValue));
        configPanel = new ConfigPanel(api, cookieCenter, cookieTableModel, cookieInjector);

        api.http().registerHttpHandler(cookieInjector);

        api.userInterface().registerSuiteTab("Cookie Center", configPanel);
        api.logging().logToOutput("Extension initialized");
    }
}
