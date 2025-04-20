package com.madneal.cookiecenter;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.io.PrintWriter;

import burp.IBurpExtender;
import burp.ITab;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private ConfigPanel configPanel;
    private CookieTableModel cookieTableModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("Cookie Center");
        api.logging().logToOutput("Extension loading...");

        configPanel = new ConfigPanel(api);

        HttpHandler cookieInjector = new CookieInjector(cookieTableModel);
        api.http().registerHttpHandler(cookieInjector);

        api.userInterface().registerSuiteTab("Cookie Center", configPanel);
        api.logging().logToOutput("Extension initialized");
    }
}