package com.madneal.cookiecenter;

import java.util.ArrayList;
import java.util.List;

public class CookieCenter {
    private final List<CookieEntry> entries = new ArrayList<>();

    public synchronized int size() {
        return entries.size();
    }

    public synchronized CookieEntry getEntry(int row) {
        if (row < 0 || row >= entries.size()) {
            return null;
        }
        return copyOf(entries.get(row));
    }

    public synchronized List<CookieEntry> getEntries() {
        List<CookieEntry> snapshot = new ArrayList<>();
        for (CookieEntry entry : entries) {
            snapshot.add(copyOf(entry));
        }
        return snapshot;
    }

    public synchronized void addEntry(CookieEntry entry) {
        entries.add(normalizedCopyOf(entry));
    }

    public synchronized void removeEntry(int row) {
        if (row >= 0 && row < entries.size()) {
            entries.remove(row);
        }
    }

    public synchronized void updateEntry(int row, CookieEntry entry) {
        if (row >= 0 && row < entries.size()) {
            entries.set(row, normalizedCopyOf(entry));
        }
    }

    public synchronized void setEntries(List<CookieEntry> newEntries) {
        entries.clear();
        if (newEntries == null) {
            return;
        }

        for (CookieEntry entry : newEntries) {
            entries.add(normalizedCopyOf(entry));
        }
    }

    public synchronized int findByHost(String host) {
        String normalizedHost = normalizeHost(host);
        for (int i = 0; i < entries.size(); i++) {
            if (normalizeHost(entries.get(i).getHost()).equals(normalizedHost)) {
                return i;
            }
        }
        return -1;
    }

    public synchronized CookieEntry findMatchingCookie(String host) {
        String normalizedHost = normalizeHost(host);
        CookieEntry bestMatch = null;
        int bestHostLength = -1;

        for (CookieEntry entry : entries) {
            if (!entry.isEnabled() || entry.getCookieValue() == null || entry.getCookieValue().trim().isEmpty()) {
                continue;
            }

            String entryHost = normalizeHost(entry.getHost());
            if (entryHost.isEmpty()) {
                continue;
            }

            boolean exactMatch = normalizedHost.equals(entryHost);
            boolean subdomainMatch = entry.isIncludeSubdomains() && normalizedHost.endsWith("." + entryHost);
            if ((exactMatch || subdomainMatch) && entryHost.length() > bestHostLength) {
                bestMatch = entry;
                bestHostLength = entryHost.length();
            }
        }

        return bestMatch == null ? null : copyOf(bestMatch);
    }

    public synchronized void setEnabled(int row, boolean enabled) {
        CookieEntry entry = entryAt(row);
        if (entry != null) {
            entry.setEnabled(enabled);
        }
    }

    public synchronized void setHost(int row, String host) {
        CookieEntry entry = entryAt(row);
        if (entry != null) {
            entry.setHost(normalizeHost(host));
        }
    }

    public synchronized void setIncludeSubdomains(int row, boolean includeSubdomains) {
        CookieEntry entry = entryAt(row);
        if (entry != null) {
            entry.setIncludeSubdomains(includeSubdomains);
        }
    }

    public synchronized void setCookieValue(int row, String cookieValue) {
        CookieEntry entry = entryAt(row);
        if (entry != null) {
            entry.setCookieValue(cookieValue == null ? "" : cookieValue.trim());
        }
    }

    public static String normalizeHost(String host) {
        if (host == null) {
            return "";
        }

        String normalized = host.trim().toLowerCase();
        normalized = normalized.replaceFirst("^https?://", "");
        int pathIndex = normalized.indexOf('/');
        if (pathIndex >= 0) {
            normalized = normalized.substring(0, pathIndex);
        }
        int portIndex = normalized.lastIndexOf(':');
        if (portIndex > -1 && normalized.indexOf(':') == portIndex) {
            normalized = normalized.substring(0, portIndex);
        }
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private CookieEntry entryAt(int row) {
        if (row < 0 || row >= entries.size()) {
            return null;
        }
        return entries.get(row);
    }

    private CookieEntry normalizedCopyOf(CookieEntry entry) {
        if (entry == null) {
            return new CookieEntry("", "", true, true);
        }
        return new CookieEntry(
                normalizeHost(entry.getHost()),
                entry.getCookieValue() == null ? "" : entry.getCookieValue().trim(),
                entry.isEnabled(),
                entry.isIncludeSubdomains()
        );
    }

    private CookieEntry copyOf(CookieEntry entry) {
        return new CookieEntry(
                entry.getHost(),
                entry.getCookieValue(),
                entry.isEnabled(),
                entry.isIncludeSubdomains()
        );
    }
}
