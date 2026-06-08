package com.madneal.cookiecenter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ConfigPanel extends JPanel {
    private final MontoyaApi api;
    private final CookieCenter cookieCenter;
    private final CookieTableModel tableModel;
    private final JTable table;
    private final JLabel statusLabel = new JLabel(" ");

    public ConfigPanel(MontoyaApi api, CookieCenter cookieCenter, CookieTableModel tableModel) {
        this.api = api;
        this.cookieCenter = cookieCenter;
        this.tableModel = tableModel;
        this.table = new JTable(tableModel);

        setLayout(new BorderLayout(0, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));

        // Create table
        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(24);
        configureColumns();

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
        removeButton.addActionListener(e -> removeSelectedRows());

        buttonPanel.add(addButton);
        buttonPanel.add(importCurlButton);
        buttonPanel.add(removeButton);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        statusLabel.setBorder(new EmptyBorder(0, 2, 0, 0));
        bottomPanel.add(statusLabel, BorderLayout.WEST);

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.NORTH);
        add(bottomPanel, BorderLayout.SOUTH);

        // Load saved entries
        loadSavedEntries();

        tableModel.addTableModelListener(e -> saveConfiguration());
    }

    private void showAddDialog() {
        Frame parentFrame = (Frame) SwingUtilities.getWindowAncestor(this);
        AddCookieDialog dialog = new AddCookieDialog(parentFrame);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            String host = dialog.getHost();
            String cookie = dialog.getCookie();

            if (!host.isEmpty() && !cookie.isEmpty()) {
                upsertEntry(new CookieEntry(CookieCenter.normalizeHost(host), cookie, true, dialog.isIncludeSubdomains()));
            }
        }
    }

    private void saveConfiguration() {
        PersistedObject settings = api.persistence().extensionData();
        List<CookieEntry> entries = cookieCenter.getEntries();

        // Save entries count
        settings.setInteger("count", entries.size());

        // Save each entry
        for (int i = 0; i < entries.size(); i++) {
            CookieEntry entry = entries.get(i);
            settings.setString("host_" + i, entry.getHost());
            settings.setString("cookie_" + i, entry.getCookieValue());
            settings.setString("enabled_" + i, Boolean.toString(entry.isEnabled()));
            settings.setString("subdomains_" + i, Boolean.toString(entry.isIncludeSubdomains()));
        }

        statusLabel.setText("Saved " + entries.size() + " cookie entr" + (entries.size() == 1 ? "y" : "ies"));
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
                String normalizedHost = CookieCenter.normalizeHost(host);
                boolean imported = upsertEntry(new CookieEntry(normalizedHost, cookie, true, true));
                if (!imported) {
                    return;
                }

                // Show success message
                JOptionPane.showMessageDialog(this,
                        "Successfully imported:\nHost: " + normalizedHost + "\nCookie: " + cookie,
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
            if (host == null || cookie == null || host.trim().isEmpty() || cookie.trim().isEmpty()) {
                continue;
            }

            boolean enabled = getBooleanSetting(settings, "enabled_" + i, true);
            boolean includeSubdomains = getBooleanSetting(settings, "subdomains_" + i, true);
            entries.add(new CookieEntry(CookieCenter.normalizeHost(host), cookie.trim(), enabled, includeSubdomains));
        }

        tableModel.setEntries(entries);
        statusLabel.setText("Loaded " + entries.size() + " cookie entr" + (entries.size() == 1 ? "y" : "ies"));
    }

    private void configureColumns() {
        TableColumnModel columns = table.getColumnModel();
        columns.getColumn(0).setPreferredWidth(70);
        columns.getColumn(0).setMaxWidth(90);
        columns.getColumn(1).setPreferredWidth(220);
        columns.getColumn(2).setPreferredWidth(95);
        columns.getColumn(2).setMaxWidth(120);
        columns.getColumn(3).setPreferredWidth(520);
    }

    private void removeSelectedRows() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }

        Integer[] modelRows = Arrays.stream(selectedRows)
                .map(table::convertRowIndexToModel)
                .boxed()
                .toArray(Integer[]::new);
        Arrays.sort(modelRows, Collections.reverseOrder());

        for (int modelRow : modelRows) {
            tableModel.removeEntry(modelRow);
        }
    }

    private boolean upsertEntry(CookieEntry entry) {
        int existingRow = cookieCenter.findByHost(entry.getHost());
        if (existingRow >= 0) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "A cookie entry for " + entry.getHost() + " already exists. Replace it?",
                    "Replace Cookie",
                    JOptionPane.YES_NO_OPTION);
            if (choice != JOptionPane.YES_OPTION) {
                return false;
            }
            tableModel.updateEntry(existingRow, entry);
            selectModelRow(existingRow);
            return true;
        }

        tableModel.addEntry(entry);
        selectModelRow(tableModel.getRowCount() - 1);
        return true;
    }

    private void selectModelRow(int modelRow) {
        int viewRow = table.convertRowIndexToView(modelRow);
        if (viewRow >= 0) {
            table.setRowSelectionInterval(viewRow, viewRow);
            table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
        }
    }

    private boolean getBooleanSetting(PersistedObject settings, String key, boolean defaultValue) {
        try {
            String value = settings.getString(key);
            return value == null ? defaultValue : Boolean.parseBoolean(value);
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

}
