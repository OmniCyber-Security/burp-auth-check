package com.omnicybersecurity.authcheck.ui;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The starter scripts offered from the Identities panel.
 *
 * <p>These are the files in the repository's {@code scripts/} directory, copied
 * into the jar by the build. They were previously duplicated as string constants
 * here, which meant every edit had to be made twice and the two drifted.
 *
 * <p>A jar cannot list a directory, so the build also writes an
 * {@code index.txt} naming the files. Each script's menu entry comes from the
 * first line of prose in its opening comment, so the file stays plain Groovy
 * with no metadata syntax to remember.
 */
public final class ScriptTemplates {

    private static final String RESOURCE_DIR = "/auth-check-scripts/";
    private static final String INDEX = RESOURCE_DIR + "index.txt";

    /** Loaded once; the contents cannot change without reloading the jar. */
    private static volatile Map<String, String> cached;

    private ScriptTemplates() {
    }

    /** Template display name to script body, in the order the build indexed them. */
    public static Map<String, String> all() {
        Map<String, String> templates = cached;
        if (templates == null) {
            templates = load();
            cached = templates;
        }
        return templates;
    }

    private static Map<String, String> load() {
        Map<String, String> templates = new LinkedHashMap<>();
        for (String fileName : readIndex()) {
            String body = readResource(RESOURCE_DIR + fileName);
            if (body == null || body.isBlank()) {
                continue;
            }
            templates.put(uniqueTitle(templates, titleOf(body, fileName)), body);
        }
        return templates;
    }

    private static List<String> readIndex() {
        List<String> names = new ArrayList<>();
        String index = readResource(INDEX);
        if (index == null) {
            return names;
        }
        for (String line : index.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                names.add(trimmed);
            }
        }
        return names;
    }

    private static String readResource(String path) {
        try (InputStream in = ScriptTemplates.class.getResourceAsStream(path)) {
            if (in == null) {
                return null;
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString();
            }
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * The first line of prose in the script's opening comment, which is the
     * one-line summary each example already starts with. Falls back to the file
     * name so an example without a comment still gets a sensible entry.
     */
    static String titleOf(String body, String fileName) {
        int examined = 0;
        for (String rawLine : body.split("\\r?\\n")) {
            if (examined++ > 12) {
                break;
            }
            String line = rawLine.trim();
            if (line.isEmpty() || line.equals("/*") || line.equals("*/") || line.equals("*")) {
                continue;
            }
            if (line.startsWith("/*")) {
                line = line.substring(2).trim();
            } else if (line.startsWith("*/")) {
                continue;
            } else if (line.startsWith("*")) {
                line = line.substring(1).trim();
            } else if (line.startsWith("//")) {
                line = line.substring(2).trim();
            } else {
                // Reached code before any prose.
                break;
            }
            if (!line.isEmpty()) {
                return abbreviate(stripTrailingStop(line));
            }
        }
        return prettifyFileName(fileName);
    }

    /** Keeps a wrapped opening sentence from becoming an unreadable menu entry. */
    private static String abbreviate(String title) {
        return title.length() <= 70 ? title : title.substring(0, 69).trim() + "\u2026";
    }

    private static String stripTrailingStop(String title) {
        return title.endsWith(".") ? title.substring(0, title.length() - 1) : title;
    }

    private static String prettifyFileName(String fileName) {
        String base = fileName.endsWith(".groovy")
                ? fileName.substring(0, fileName.length() - ".groovy".length())
                : fileName;
        String spaced = base.replace('-', ' ').replace('_', ' ').trim();
        return spaced.isEmpty()
                ? fileName
                : spaced.substring(0, 1).toUpperCase(Locale.ROOT) + spaced.substring(1);
    }

    /** Two scripts opening with the same sentence must still both be listed. */
    private static String uniqueTitle(Map<String, String> existing, String title) {
        if (!existing.containsKey(title)) {
            return title;
        }
        int suffix = 2;
        while (existing.containsKey(title + " (" + suffix + ")")) {
            suffix++;
        }
        return title + " (" + suffix + ")";
    }
}
