package com.madneal.cookiecenter;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class CookieTableModel extends AbstractTableModel {
    private final String[] columnNames = {"Enabled", "Host", "Subdomains", "Cookie"};
    private final CookieCenter cookieCenter;

    public CookieTableModel(CookieCenter cookieCenter) {
        this.cookieCenter = cookieCenter;
    }

    @Override
    public int getRowCount() {
        return cookieCenter.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0 || columnIndex == 2) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return true;
    }

    @Override
    public Object getValueAt(int row, int column) {
        CookieEntry entry = cookieCenter.getEntry(row);
        if (entry == null) {
            return "";
        }
        switch (column) {
            case 0:
                return entry.isEnabled();
            case 1:
                return entry.getHost();
            case 2:
                return entry.isIncludeSubdomains();
            case 3:
                return entry.getCookieValue();
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        switch (column) {
            case 0:
                cookieCenter.setEnabled(row, Boolean.TRUE.equals(value));
                break;
            case 1:
                cookieCenter.setHost(row, value == null ? "" : value.toString());
                break;
            case 2:
                cookieCenter.setIncludeSubdomains(row, Boolean.TRUE.equals(value));
                break;
            case 3:
                cookieCenter.setCookieValue(row, value == null ? "" : value.toString());
                break;
            default:
                return;
        }
        fireTableCellUpdated(row, column);
    }

    public void addEntry(CookieEntry entry) {
        int row = cookieCenter.size();
        cookieCenter.addEntry(entry);
        fireTableRowsInserted(row, row);
    }

    public void removeEntry(int row) {
        if (row >= 0 && row < cookieCenter.size()) {
            cookieCenter.removeEntry(row);
            fireTableRowsDeleted(row, row);
        }
    }

    public void updateEntry(int row, CookieEntry entry) {
        if (row >= 0 && row < cookieCenter.size()) {
            cookieCenter.updateEntry(row, entry);
            fireTableRowsUpdated(row, row);
        }
    }

    public void setEntries(List<CookieEntry> newEntries) {
        cookieCenter.setEntries(newEntries);
        fireTableDataChanged();
    }
}
