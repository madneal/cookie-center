package com.madneal.cookiecenter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ConfigPanel extends JPanel implements CookieCaptureListener {
    private final MontoyaApi api;
    private final CookieCenter cookieCenter;
    private final CookieTableModel tableModel;
    private final CookieInjector cookieInjector;
    private final JTable table;
    private final JLabel statusLabel = new JLabel(" ");
    private final JCheckBox autoCaptureCheckBox = new JCheckBox("Auto capture from Proxy");
    private boolean loaded;

    public ConfigPanel(MontoyaApi api, CookieCenter cookieCenter, CookieTableModel tableModel, CookieInjector cookieInjector) {
        this.api = api;
        this.cookieCenter = cookieCenter;
        this.tableModel = tableModel;
        this.cookieInjector = cookieInjector;
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

        JButton importJarButton = new JButton("Import from Burp Cookie Jar");
        importJarButton.setToolTipText("Read cookies captured by Burp's session cookie jar");
        importJarButton.addActionListener(e -> importFromCookieJar());

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> removeSelectedRows());

        autoCaptureCheckBox.setToolTipText("Automatically update entries from browser requests passing through Proxy");
        autoCaptureCheckBox.addActionListener(e -> updateAutoCaptureSetting());

        buttonPanel.add(addButton);
        buttonPanel.add(importCurlButton);
        buttonPanel.add(importJarButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(autoCaptureCheckBox);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        statusLabel.setBorder(new EmptyBorder(0, 2, 0, 0));
        bottomPanel.add(statusLabel, BorderLayout.WEST);

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.NORTH);
        add(bottomPanel, BorderLayout.SOUTH);

        // Load saved entries
        loadSavedEntries();
        loadAutoCaptureSetting();
        loaded = true;

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
                upsertEntry(new CookieEntry(CookieCenter.normalizeHost(host), cookie, true, dialog.isIncludeSubdomains()), true);
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
        settings.setString("auto_capture_proxy", Boolean.toString(autoCaptureCheckBox.isSelected()));

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
                boolean imported = upsertEntry(new CookieEntry(normalizedHost, cookie, true, true), true);
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

    private void importFromCookieJar() {
        List<Cookie> cookies = api.http().cookieJar().cookies();
        Map<String, LinkedHashMap<String, String>> cookiesByHost = new LinkedHashMap<>();
        Map<String, Boolean> subdomainsByHost = new LinkedHashMap<>();

        for (Cookie cookie : cookies) {
            String domain = cookie.domain();
            String host = CookieCenter.normalizeHost(domain);
            if (host.isEmpty() || cookie.name() == null || cookie.name().trim().isEmpty()) {
                continue;
            }
            if (cookie.value() == null || cookie.value().trim().isEmpty()) {
                continue;
            }

            LinkedHashMap<String, String> hostCookies = cookiesByHost.computeIfAbsent(host, ignored -> new LinkedHashMap<>());
            hostCookies.put(cookie.name().trim(), cookie.value().trim());
            subdomainsByHost.put(host, subdomainsByHost.getOrDefault(host, false) || domain.startsWith("."));
        }

        int imported = 0;
        for (Map.Entry<String, LinkedHashMap<String, String>> entry : cookiesByHost.entrySet()) {
            String cookieHeader = buildCookieHeader(entry.getValue());
            if (!cookieHeader.isEmpty()) {
                upsertEntry(new CookieEntry(entry.getKey(), cookieHeader, true, subdomainsByHost.getOrDefault(entry.getKey(), true)), false);
                imported++;
            }
        }

        if (imported == 0) {
            JOptionPane.showMessageDialog(this,
                    "Burp Cookie Jar does not contain importable cookies yet.",
                    "No Cookies Found",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        statusLabel.setText("Imported " + imported + " host entr" + (imported == 1 ? "y" : "ies") + " from Burp Cookie Jar");
        JOptionPane.showMessageDialog(this,
                "Imported or updated " + imported + " host entr" + (imported == 1 ? "y" : "ies") + " from Burp Cookie Jar.",
                "Import Successful",
                JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void cookieCaptured(String host, String cookieValue) {
        String normalizedHost = CookieCenter.normalizeHost(host);
        String normalizedCookie = cookieValue == null ? "" : cookieValue.trim();
        if (normalizedHost.isEmpty() || normalizedCookie.isEmpty()) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            int existingRow = cookieCenter.findByHost(normalizedHost);
            CookieEntry existingEntry = cookieCenter.getEntry(existingRow);
            if (existingEntry != null && normalizedCookie.equals(existingEntry.getCookieValue())) {
                return;
            }

            upsertEntry(new CookieEntry(normalizedHost, normalizedCookie, true, true), false);
            statusLabel.setText("Auto captured cookie for " + normalizedHost);
        });
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

    private void loadAutoCaptureSetting() {
        PersistedObject settings = api.persistence().extensionData();
        boolean autoCapture = getBooleanSetting(settings, "auto_capture_proxy", false);
        autoCaptureCheckBox.setSelected(autoCapture);
        cookieInjector.setAutoCaptureEnabled(autoCapture);
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

    private boolean upsertEntry(CookieEntry entry, boolean confirmReplace) {
        int existingRow = cookieCenter.findByHost(entry.getHost());
        if (existingRow >= 0) {
            if (confirmReplace) {
                int choice = JOptionPane.showConfirmDialog(this,
                        "A cookie entry for " + entry.getHost() + " already exists. Replace it?",
                        "Replace Cookie",
                        JOptionPane.YES_NO_OPTION);
                if (choice != JOptionPane.YES_OPTION) {
                    return false;
                }
            }
            int row = tableModel.upsertEntry(entry);
            selectModelRow(row);
            return true;
        }

        int row = tableModel.upsertEntry(entry);
        selectModelRow(row);
        return true;
    }

    private void updateAutoCaptureSetting() {
        cookieInjector.setAutoCaptureEnabled(autoCaptureCheckBox.isSelected());
        if (loaded) {
            saveConfiguration();
        }
    }

    private String buildCookieHeader(LinkedHashMap<String, String> cookies) {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> cookie : cookies.entrySet()) {
            if (builder.length() > 0) {
                builder.append("; ");
            }
            builder.append(cookie.getKey()).append("=").append(cookie.getValue());
        }
        return builder.toString();
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
