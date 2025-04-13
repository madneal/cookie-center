package com.madneal.cookiecenter;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class CookieTableModel extends AbstractTableModel {
    private final String[] columnNames = {"Host", "Cookie"};
    private final List<CookieEntry> entries = new ArrayList<>();

    @Override
    public int getRowCount() {
        return entries.size();
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
    public boolean isCellEditable(int row, int column) {
        return true;
    }

    @Override
    public Object getValueAt(int row, int column) {
        CookieEntry entry = entries.get(row);
        return column == 0 ? entry.getHost() : entry.getCookieValue();
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        CookieEntry entry = entries.get(row);
        if (column == 0) {
            entry.setHost((String) value);
        } else {
            entry.setCookieValue((String) value);
        }
        fireTableCellUpdated(row, column);
    }

    public void addEntry(CookieEntry entry) {
        entries.add(entry);
        fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
    }

    public void removeEntry(int row) {
        if (row >= 0 && row < entries.size()) {
            entries.remove(row);
            fireTableRowsDeleted(row, row);
        }
    }

    public List<CookieEntry> getEntries() {
        return new ArrayList<>(entries);
    }

    public void setEntries(List<CookieEntry> newEntries) {
        entries.clear();
        if (newEntries != null) {
            entries.addAll(newEntries);
        }
        fireTableDataChanged();
    }
}
