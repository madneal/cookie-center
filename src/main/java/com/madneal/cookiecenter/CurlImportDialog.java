package com.madneal.cookiecenter;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CurlImportDialog extends JDialog {
    private JTextArea curlTextArea;
    private boolean confirmed = false;
    private String extractedHost = "";
    private String extractedCookie = "";

    public CurlImportDialog(Frame owner) {
        super(owner, "Import from curl command", true);
        initComponents();
    }

    private void initComponents() {
        // Set dialog size and layout
        setSize(550, 300);
        setLocationRelativeTo(getOwner());
        setLayout(new BorderLayout(10, 10));

        // Create instruction label
        JLabel instructionLabel = new JLabel(
                "<html>Paste a curl command to extract host and cookie values.<br/>" +
                        "The command should contain a URL and cookie header.</html>");
        instructionLabel.setBorder(new EmptyBorder(10, 10, 5, 10));

        // Create text area for curl command
        curlTextArea = new JTextArea();
        curlTextArea.setLineWrap(true);
        curlTextArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(curlTextArea);
        scrollPane.setBorder(new EmptyBorder(0, 10, 0, 10));

        // Create button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(new EmptyBorder(5, 10, 10, 10));

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());

        JButton importButton = new JButton("Extract and Import");
        importButton.addActionListener(e -> {
            if (parseCurlCommand()) {
                confirmed = true;
                dispose();
            }
        });

        buttonPanel.add(importButton);
        buttonPanel.add(cancelButton);

        // Add components to dialog
        add(instructionLabel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private boolean parseCurlCommand() {
        String curlCommand = curlTextArea.getText().trim();

        if (curlCommand.isEmpty()) {
            showError("Please enter a curl command.");
            return false;
        }

        // Extract host from URL
        String hostPattern = "(?:curl\\s+(?:-X\\s+[A-Z]+\\s+)?['\"](https?://)?([^/'\"]+))?";
        Pattern hostRegex = Pattern.compile(hostPattern);
        Matcher hostMatcher = hostRegex.matcher(curlCommand);

        if (hostMatcher.find() && hostMatcher.group(2) != null) {
            extractedHost = hostMatcher.group(2);
        } else {
            // Try alternative pattern for different curl syntax
            Pattern altHostPattern = Pattern.compile("(?:curl\\s+(?:-X\\s+[A-Z]+\\s+)?(?:https?://)?([^/\\s]+))");
            Matcher altHostMatcher = altHostPattern.matcher(curlCommand);
            if (altHostMatcher.find() && altHostMatcher.group(1) != null) {
                extractedHost = altHostMatcher.group(1);
            } else {
                showError("Could not find host in the curl command.");
                return false;
            }
        }

        // Extract cookie from headers
        String cookiePattern = "-H\\s+['\"]Cookie:\\s*([^'\"]+)['\"]";
        Pattern cookieRegex = Pattern.compile(cookiePattern);
        Matcher cookieMatcher = cookieRegex.matcher(curlCommand);

        if (cookieMatcher.find()) {
            extractedCookie = cookieMatcher.group(1).trim();
        } else {
            // Try alternative pattern with --cookie
            Pattern altCookiePattern = Pattern.compile("--cookie\\s+['\"]([^'\"]+)['\"]");
            Matcher altCookieMatcher = altCookiePattern.matcher(curlCommand);
            if (altCookieMatcher.find()) {
                extractedCookie = altCookieMatcher.group(1).trim();
            } else {
                showError("Could not find cookie header in the curl command.");
                return false;
            }
        }

        return true;
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this,
                message,
                "Parsing Error",
                JOptionPane.ERROR_MESSAGE);
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getExtractedHost() {
        return extractedHost;
    }

    public String getExtractedCookie() {
        return extractedCookie;
    }
}
