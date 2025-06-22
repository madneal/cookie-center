package com.madneal.cookiecenter;

import javax.swing.*;
import java.awt.*;

public class AddCookieDialog extends JDialog {
    private JTextField hostField = new JTextField(20);
    private JTextField cookieField = new JTextField(20);
    private boolean confirmed = false;

    public AddCookieDialog(Frame owner) {
        super(owner, "Add Cookie", true);

        // Main panel with improved layout
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Title label
        JLabel titleLabel = new JLabel("Add New Cookie");
        titleLabel.setFont(new Font(titleLabel.getFont().getName(), Font.BOLD, 14));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(titleLabel);
        mainPanel.add(Box.createVerticalStrut(10));

        // Host field with improved layout
        JPanel hostPanel = new JPanel();
        hostPanel.setLayout(new BoxLayout(hostPanel, BoxLayout.X_AXIS));
        hostPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel hostLabel = new JLabel("Host:");
        hostLabel.setPreferredSize(new Dimension(80, hostLabel.getPreferredSize().height));
        hostPanel.add(hostLabel);
        hostPanel.add(Box.createHorizontalStrut(5));
        hostPanel.add(hostField);
        mainPanel.add(hostPanel);
        mainPanel.add(Box.createVerticalStrut(10));

        // Cookie field with improved layout
        JPanel cookiePanel = new JPanel();
        cookiePanel.setLayout(new BoxLayout(cookiePanel, BoxLayout.X_AXIS));
        cookiePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel cookieLabel = new JLabel("Cookie:");
        cookieLabel.setPreferredSize(new Dimension(80, cookieLabel.getPreferredSize().height));
        cookiePanel.add(cookieLabel);
        cookiePanel.add(Box.createHorizontalStrut(5));
        cookiePanel.add(cookieField);
        mainPanel.add(cookiePanel);
        mainPanel.add(Box.createVerticalStrut(15));

        // Buttons with improved layout
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.X_AXIS));
        buttonPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");
        
        // Set preferred button sizes
        Dimension buttonSize = new Dimension(100, 30);
        okButton.setPreferredSize(buttonSize);
        cancelButton.setPreferredSize(buttonSize);
        
        okButton.addActionListener(e -> {
            if (!hostField.getText().trim().isEmpty() && !cookieField.getText().trim().isEmpty()) {
                confirmed = true;
                dispose();
            } else {
                JOptionPane.showMessageDialog(this, 
                    "Please fill in both host and cookie fields.",
                    "Missing Information",
                    JOptionPane.WARNING_MESSAGE);
            }
        });

        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(Box.createHorizontalGlue());
        buttonPanel.add(okButton);
        buttonPanel.add(Box.createHorizontalStrut(10));
        buttonPanel.add(cancelButton);
        buttonPanel.add(Box.createHorizontalGlue());
        
        mainPanel.add(buttonPanel);

        // Set up dialog
        add(mainPanel);
        pack();
        setLocationRelativeTo(owner);
        setResizable(false);
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