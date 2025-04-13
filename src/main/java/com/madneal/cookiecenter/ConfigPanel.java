package com.madneal.cookiecenter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
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

        setLayout(new BorderLayout(10, 10));

        // Create table
        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);

        // Create button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
            tableModel.addEntry(new CookieEntry("example.com", "sessionid=value"));
            int lastRow = tableModel.getRowCount() - 1;
            table.setRowSelectionInterval(lastRow, lastRow);
        });

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            tableModel.removeEntry(selectedRow);
        });

        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> saveConfiguration());

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(saveButton);

        // Add components to panel
        add(new JLabel("Configure host-specific cookie values:"), BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // Load saved entries
        loadSavedEntries();
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
