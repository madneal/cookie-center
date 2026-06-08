package com.madneal.cookiecenter;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.net.URI;
import java.net.URISyntaxException;
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
        String curlCommand = curlTextArea.getText().trim()
                .replace("\\\r\n", " ")
                .replace("\\\n", " ")
                .replace('\r', ' ')
                .replace('\n', ' ');

        if (curlCommand.isEmpty()) {
            showError("Please enter a curl command.");
            return false;
        }

        Pattern urlPattern = Pattern.compile("https?://[^\\s'\"]+");
        Matcher urlMatcher = urlPattern.matcher(curlCommand);

        if (urlMatcher.find()) {
            extractedHost = extractHost(urlMatcher.group());
            
            if (extractedHost.isEmpty() || extractedHost.contains("=") || extractedHost.contains(";")) {
                showError("Host extraction failed. The extracted value looks like a cookie: " + extractedHost + 
                         "\n\nPlease check your curl command format.");
                return false;
            }
        } else {
            showError("Could not find a valid URL in the curl command.\n\nMake sure the URL starts with http:// or https://");
            return false;
        }

        Pattern cookiePattern = Pattern.compile(
                "(?:-(?:H)|--header)\\s+(['\"])(?i:Cookie)\\s*:\\s*(.*?)\\1|" +
                "(?:--cookie|-b)\\s+(['\"])(.*?)\\3"
        );
        Matcher cookieMatcher = cookiePattern.matcher(curlCommand);

        if (cookieMatcher.find()) {
            extractedCookie = cookieMatcher.group(2) != null
                    ? cookieMatcher.group(2).trim()
                    : cookieMatcher.group(4).trim();
            
            if (extractedCookie.isEmpty()) {
                showError("Could not extract cookie value from the curl command.");
                return false;
            }
            
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

    private String extractHost(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host != null) {
                return CookieCenter.normalizeHost(host);
            }

            String authority = uri.getRawAuthority();
            if (authority != null) {
                int atIndex = authority.lastIndexOf('@');
                if (atIndex >= 0) {
                    authority = authority.substring(atIndex + 1);
                }
                int portIndex = authority.lastIndexOf(':');
                if (portIndex > -1 && authority.indexOf(':') == portIndex) {
                    authority = authority.substring(0, portIndex);
                }
                return CookieCenter.normalizeHost(authority);
            }
        } catch (URISyntaxException ignored) {
            // Fall back to regex extraction below.
        }

        Matcher fallbackMatcher = Pattern.compile("https?://([^/\\s'\"]+)").matcher(url);
        if (!fallbackMatcher.find()) {
            return "";
        }
        return CookieCenter.normalizeHost(fallbackMatcher.group(1));
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
