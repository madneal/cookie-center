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

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private ConfigPanel configPanel;
    private ConfigManager configManager;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("Cookie Center");
        api.logging().logToOutput("Extension loading...");

        configManager = new ConfigManager(api);
        configPanel = new ConfigPanel(configManager);

        api.userInterface().registerSuiteTab("Cookie Center", configPanel);
        api.logging().logToOutput("Extension initialized");
    }
}