package com.madneal.cookiecenter;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.io.PrintWriter;

import burp.IBurpExtender;
import burp.ITab;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.api.montoya.BurpExtension;

public class BurpExtender implements  IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ConfigPanel configPanel;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private ConfigManager configManager;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Save the callbacks object
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Set up the extension name
        callbacks.setExtensionName("My Custom Burp Plugin");

        // Initialize stdout and stderr for debugging
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // Initialize the configuration manager with Burp's persistent storage
        configManager = new ConfigManager(callbacks);

        // Create the config UI
        SwingUtilities.invokeLater(() -> {
            // Create config panel with the config manager
            configPanel = new ConfigPanel(configManager);

            // Add the custom tab to Burp's UI
            callbacks.addSuiteTab((ITab) BurpExtender.this);

            stdout.println("Plugin loaded successfully");
        });
    }

    @Override
    public String getTabCaption() {
        return "Cookie Center";
    }

    @Override
    public Component getUiComponent() {
        return configPanel;
    }
}
