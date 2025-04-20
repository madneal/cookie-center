package com.madneal.cookiecenter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ConfigPanel extends JPanel {
    private final MontoyaApi api;
    private final CookieTableModel tableModel;
    private final JTable table;

    public ConfigPanel(MontoyaApi api) {
        this.api = api;
        this.tableModel = new CookieTableModel();
        this.table = new JTable(tableModel);

        setLayout(new BorderLayout(0, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));

        // Create table
        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);

        // Create button panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        buttonPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                new EmptyBorder(5, 0, 10, 0)
        ));

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> showAddDialog());

        JButton importCurlButton = new JButton("Import from curl");
        importCurlButton.setToolTipText("Extract host and cookie from a curl command");
        importCurlButton.addActionListener(e -> importFromCurl());

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            tableModel.removeEntry(selectedRow);
        });

        buttonPanel.add(addButton);
        buttonPanel.add(importCurlButton);
        buttonPanel.add(removeButton);

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.NORTH);

        tableModel.addTableModelListener(e -> saveConfiguration());

        // Load saved entries
        loadSavedEntries();
    }

    private void showAddDialog() {
        Frame parentFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        AddCookieDialog dialog = new AddCookieDialog(parentFrame);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            String host = dialog.getHost();
            String cookie = dialog.getCookie();

            if (!host.isEmpty() && !cookie.isEmpty()) {
                tableModel.addEntry(new CookieEntry(host, cookie));
                int lastRow = tableModel.getRowCount() - 1;
                table.setRowSelectionInterval(lastRow, lastRow);
            }
        }
    }

    private void saveConfiguration() {
        PersistedObject settings = api.persistence().extensionData();
        List<CookieEntry> entries = tableModel.getEntries();

        // Save entries count
        settings.setInteger("count", entries.size());

        // Save each entry
        for (int i = 0; i < entries.size(); i++) {
            CookieEntry entry = entries.get(i);
            settings.setString("host_" + i, entry.getHost());
            settings.setString("cookie_" + i, entry.getCookieValue());
        }

        JOptionPane.showMessageDialog(this, "Configuration saved successfully");
    }

    private void importFromCurl() {
        // Get the parent frame for the dialog
        Frame parentFrame = (Frame) SwingUtilities.getWindowAncestor(this);

        // Create and show the curl import dialog
        CurlImportDialog dialog = new CurlImportDialog(parentFrame);
        dialog.setVisible(true);

        // If the user confirmed the import and we have data
        if (dialog.isConfirmed()) {
            String host = dialog.getExtractedHost();
            String cookie = dialog.getExtractedCookie();

            if (!host.isEmpty() && !cookie.isEmpty()) {
                // Add the extracted entry to the table
                tableModel.addEntry(new CookieEntry(host, cookie));

                // Select the new entry
                int lastRow = tableModel.getRowCount() - 1;
                table.setRowSelectionInterval(lastRow, lastRow);
                table.scrollRectToVisible(table.getCellRect(lastRow, 0, true));

                // Show success message
                JOptionPane.showMessageDialog(this,
                        "Successfully imported:\nHost: " + host + "\nCookie: " + cookie,
                        "Import Successful",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void loadSavedEntries() {
        PersistedObject settings = api.persistence().extensionData();
        int count = 0;
        try {
            count = settings.getInteger("count");
        } catch (Exception ignored) {

        }

        List<CookieEntry> entries = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String host = settings.getString("host_" + i);
            String cookie = settings.getString("cookie_" + i);
            entries.add(new CookieEntry(host, cookie));
        }

        tableModel.setEntries(entries);
    }
}
