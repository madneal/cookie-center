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
                "Paste a curl command to extract host and cookie values.");
        instructionLabel.setBorder(new EmptyBorder(10, 10, 5, 10));

        curlTextArea = new JTextArea();
        curlTextArea.setLineWrap(true);
        curlTextArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(curlTextArea);
        scrollPane.setBorder(new EmptyBorder(0, 10, 0, 10));

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

        // Extract host from URL with a single, more robust pattern
        Pattern hostPattern = Pattern.compile("curl\\s+(?:.*?\\s+)?(?:https?://)?([^/\\s'\"]+)");
        Matcher hostMatcher = hostPattern.matcher(curlCommand);

        if (hostMatcher.find()) {
            extractedHost = hostMatcher.group(1);
        } else {
            showError("Could not find host in the curl command.");
            return false;
        }

        // Extract cookie with a unified pattern that supports -H "Cookie:", --cookie, and -b
        Pattern cookiePattern = Pattern.compile("(?:-H\\s+['\"]Cookie:\\s*([^'\"]+)['\"]|--cookie\\s+['\"]([^'\"]+)['\"]|-b\\s+['\"]([^'\"]+)['\"])");
        Matcher cookieMatcher = cookiePattern.matcher(curlCommand);

        if (cookieMatcher.find()) {
            // Get the first non-null group from the three capturing groups
            extractedCookie = cookieMatcher.group(1) != null ? cookieMatcher.group(1) :
                    cookieMatcher.group(2) != null ? cookieMatcher.group(2) :
                            cookieMatcher.group(3);

            extractedCookie = extractedCookie.trim();
            return true;
        } else {
            showError("Could not find cookie header in the curl command.");
            return false;
        }
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
