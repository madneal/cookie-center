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

        // Debug: Log the curl command being parsed
        System.out.println("Parsing curl command: " + curlCommand);

        // Extract host from URL - completely rewritten approach
        // First, find the URL pattern in the curl command
        Pattern urlPattern = Pattern.compile("https?://([^/\\s'\"]+)");
        Matcher urlMatcher = urlPattern.matcher(curlCommand);

        if (urlMatcher.find()) {
            extractedHost = urlMatcher.group(1);
            // Remove any trailing dots or invalid characters
            extractedHost = extractedHost.replaceAll("[.]$", "");
            
            // Additional validation: make sure we didn't extract a cookie value as host
            if (extractedHost.contains("=") || extractedHost.contains(";")) {
                // This looks like a cookie value, not a host
                showError("Host extraction failed. The extracted value looks like a cookie: " + extractedHost + 
                         "\n\nPlease check your curl command format.");
                return false;
            }
            
            System.out.println("Extracted host: " + extractedHost);
        } else {
            showError("Could not find a valid URL in the curl command.\n\nMake sure the URL starts with http:// or https://");
            return false;
        }

        // Extract cookie with improved pattern that handles various formats
        // Pattern 1: -H "Cookie: value"
        // Pattern 2: -H 'Cookie: value'
        // Pattern 3: --cookie "value"
        // Pattern 4: --cookie 'value'
        // Pattern 5: -b "value"
        // Pattern 6: -b 'value'
        Pattern cookiePattern = Pattern.compile(
            "(?:-H\\s+['\"]Cookie:\\s*([^'\"]+)['\"]|" +
            "-H\\s+['\"]Cookie:\\s*([^'\"]+)['\"]|" +
            "--cookie\\s+['\"]([^'\"]+)['\"]|" +
            "--cookie\\s+['\"]([^'\"]+)['\"]|" +
            "-b\\s+['\"]([^'\"]+)['\"]|" +
            "-b\\s+['\"]([^'\"]+)['\"])"
        );
        Matcher cookieMatcher = cookiePattern.matcher(curlCommand);

        if (cookieMatcher.find()) {
            // Get the first non-null group from the capturing groups
            for (int i = 1; i <= cookieMatcher.groupCount(); i++) {
                if (cookieMatcher.group(i) != null) {
                    extractedCookie = cookieMatcher.group(i).trim();
                    System.out.println("Extracted cookie: " + extractedCookie);
                    break;
                }
            }
            
            if (extractedCookie.isEmpty()) {
                showError("Could not extract cookie value from the curl command.");
                return false;
            }
            
            // Show success message with extracted values
            JOptionPane.showMessageDialog(this,
                "Successfully extracted:\n\nHost: " + extractedHost + "\nCookie: " + extractedCookie,
                "Extraction Successful",
                JOptionPane.INFORMATION_MESSAGE);
            
            return true;
        } else {
            showError("Could not find cookie header in the curl command.\n\n" +
                     "Supported formats:\n" +
                     "-H \"Cookie: session_id=abc123; user_token=xyz456\"\n" +
                     "--cookie \"session_id=abc123; user_token=xyz456\"\n" +
                     "-b \"session_id=abc123; user_token=xyz456\"\n\n" +
                     "Your command: " + curlCommand);
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
