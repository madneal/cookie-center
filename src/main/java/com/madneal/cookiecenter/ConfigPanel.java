package com.madneal.cookiecenter;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.border.EmptyBorder;

public class ConfigPanel extends JPanel {
    private final ConfigManager configManager;
    private JTextField apiKeyField;
    private JTextField apiUrlField;
    private JCheckBox enableFeatureBox;
    private JSpinner timeoutSpinner;

    public ConfigPanel(ConfigManager configManager) {
        this.configManager = configManager;

        // Set up the panel
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(20, 20, 20, 20));

        // Create the form panel
        JPanel formPanel = createFormPanel();

        // Create the save panel
        JPanel savePanel = createSavePanel();

        // Add panels to the main panel
        add(new JLabel("<html><h1>Plugin Configuration</h1></html>"), BorderLayout.NORTH);
        add(formPanel, BorderLayout.CENTER);
        add(savePanel, BorderLayout.SOUTH);
    }

    private JPanel createFormPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // API Key
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("API Key:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        apiKeyField = new JTextField(20);
        apiKeyField.setText(configManager.getSetting(ConfigManager.API_KEY));
        panel.add(apiKeyField, gbc);

        // API URL
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        panel.add(new JLabel("API URL:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        apiUrlField = new JTextField(20);
        apiUrlField.setText(configManager.getSetting(ConfigManager.API_URL));
        panel.add(apiUrlField, gbc);

        // Enable Feature Checkbox
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        enableFeatureBox = new JCheckBox("Enable Feature");
        enableFeatureBox.setSelected(configManager.getBooleanSetting(ConfigManager.ENABLE_FEATURE));
        panel.add(enableFeatureBox, gbc);

        // Timeout Setting
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        panel.add(new JLabel("Request Timeout (ms):"), gbc);

        gbc.gridx = 1;
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(
                configManager.getIntSetting(ConfigManager.TIMEOUT_MS, 5000),
                1000, 60000, 1000);
        timeoutSpinner = new JSpinner(spinnerModel);
        panel.add(timeoutSpinner, gbc);

        return panel;
    }

    private JPanel createSavePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new FlowLayout(FlowLayout.RIGHT));

        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveConfiguration();
            }
        });

        panel.add(saveButton);
        return panel;
    }

    private void saveConfiguration() {
        // Save all configuration values
        configManager.saveSetting(ConfigManager.API_KEY, apiKeyField.getText());
        configManager.saveSetting(ConfigManager.API_URL, apiUrlField.getText());
        configManager.saveSetting(ConfigManager.ENABLE_FEATURE, String.valueOf(enableFeatureBox.isSelected()));
        configManager.saveSetting(ConfigManager.TIMEOUT_MS, timeoutSpinner.getValue().toString());

        // Show confirmation
        JOptionPane.showMessageDialog(this,
                "Configuration saved successfully.\nSettings will be persisted between Burp sessions.",
                "Configuration Saved",
                JOptionPane.INFORMATION_MESSAGE);
    }
}
