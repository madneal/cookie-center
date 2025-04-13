package com.madneal.cookiecenter;

import javax.swing.*;
import java.awt.*;

public class AddCookieDialog extends JDialog {
    private JTextField hostField = new JTextField(20);
    private JTextField cookieField = new JTextField(20);
    private boolean confirmed = false;

    public AddCookieDialog(Frame owner) {
        super(owner, "Add Cookie", true);

        // Simple panel with basic layout
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Host field
        JPanel hostPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hostPanel.add(new JLabel("Host:"));
        hostPanel.add(hostField);
        panel.add(hostPanel);

        // Cookie field
        JPanel cookiePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        cookiePanel.add(new JLabel("Cookie:"));
        cookiePanel.add(cookieField);
        panel.add(cookiePanel);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");

        okButton.addActionListener(e -> {
            if (!hostField.getText().trim().isEmpty() && !cookieField.getText().trim().isEmpty()) {
                confirmed = true;
                dispose();
            }
        });

        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        panel.add(buttonPanel);

        // Set up dialog
        add(panel);
        pack();
        setLocationRelativeTo(owner);
        hostField.requestFocus();
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public String getHost() {
        return hostField.getText().trim();
    }

    public String getCookie() {
        return cookieField.getText().trim();
    }
}