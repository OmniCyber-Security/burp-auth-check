package com.omnicybersecurity.authcheck.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small string helpers shared by the config, UI and engine layers. */
public final class Text {

    private Text() {
    }

    public static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    public static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Splits a comma (or newline) separated list, trimming and dropping empties. */
    public static List<String> splitList(String csv) {
        List<String> out = new ArrayList<>();
        if (csv == null) {
            return out;
        }
        for (String part : csv.split("[,\\r\\n]")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    /** Parses status codes from a CSV, ignoring anything non-numeric. */
    public static List<Integer> splitInts(String csv) {
        List<Integer> out = new ArrayList<>();
        for (String part : splitList(csv)) {
            try {
                out.add(Integer.parseInt(part));
            } catch (NumberFormatException ignored) {
                // A half-typed setting should not break request processing.
            }
        }
        return out;
    }

    /**
     * Parses {@code Name: Value} lines into an ordered map. Lines without a
     * colon, and comment lines starting with {@code #}, are ignored.
     */
    public static Map<String, String> parseHeaderLines(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        if (text == null) {
            return out;
        }
        for (String rawLine : text.split("\\r?\\n")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (!name.isEmpty()) {
                out.put(name, value);
            }
        }
        return out;
    }

    public static String formatHeaderLines(Map<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
        }
        return sb.toString();
    }

    /** True when a credential key looks secret enough to hide in the UI by default. */
    public static boolean looksSecret(String key) {
        if (key == null) {
            return false;
        }
        String lower = key.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("pass") || lower.contains("secret") || lower.contains("token")
                || lower.contains("key") || lower.contains("otp") || lower.contains("pin")
                || lower.contains("credential");
    }

    public static String mask(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return "•".repeat(Math.min(value.length(), 12));
    }

    public static String abbreviate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, Math.max(0, max - 1)) + "…";
    }

    /** Escapes a value for a CSV cell. */
    public static String csvCell(String value) {
        String safe = nullToEmpty(value).replace("\"", "\"\"");
        return '"' + safe + '"';
    }
}
