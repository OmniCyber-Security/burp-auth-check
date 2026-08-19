package com.omnicybersecurity.authcheck.config;

import burp.api.montoya.persistence.PersistedObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Defensive reads for Burp's {@code PersistedList}.
 *
 * <p>{@code getStringList} is declared to return {@code PersistedList<String>},
 * but the elements Burp puts in it are not always {@code java.lang.String}. Type
 * erasure means adding them to a {@code List<String>} succeeds silently, and the
 * cast blows up later at an unrelated line -- which took the extension down on
 * load with a {@code ClassCastException} pointing at a for-each.
 *
 * <p>So nothing here ever declares the element type. Lists are walked as
 * {@code Object}, converted explicitly, and the results are validated against
 * something authoritative before use. New data avoids the type entirely: order is
 * written as a delimited string and read back with {@code getString}.
 */
final class PersistedLists {

    /** Separator for order strings. Never appears in an id or a header name. */
    private static final String SEPARATOR = "\n";

    private PersistedLists() {
    }

    /**
     * Reads a list of strings without ever casting an element to {@code String}.
     * Unreadable lists yield an empty result rather than an exception.
     */
    static List<String> readStrings(PersistedObject object, String key) {
        List<String> out = new ArrayList<>();
        try {
            Object raw = object.getStringList(key);
            if (raw instanceof Iterable<?> elements) {
                for (Object element : elements) {
                    if (element != null) {
                        out.add(String.valueOf(element));
                    }
                }
            }
        } catch (RuntimeException | LinkageError e) {
            // A list we cannot read is a list we do without; callers fall back to
            // an authoritative source such as childObjectKeys().
        }
        return out;
    }

    /** Reads an order written by {@link #writeOrder}, or the legacy list form. */
    static List<String> readOrder(PersistedObject object, String key) {
        String packed = object.getString(key);
        if (packed != null && !packed.isBlank()) {
            List<String> out = new ArrayList<>();
            for (String part : packed.split(SEPARATOR, -1)) {
                if (!part.isBlank()) {
                    out.add(part);
                }
            }
            return out;
        }
        // Written by an older build as a PersistedList.
        return readStrings(object, key);
    }

    /** Writes an order as a plain string, avoiding PersistedList entirely. */
    static void writeOrder(PersistedObject object, String key, Collection<String> values) {
        object.setString(key, String.join(SEPARATOR, values));
    }

    /**
     * Keeps only the entries that actually exist, in the order given, then
     * appends anything present but unordered. Junk from an unreadable order list
     * simply does not resolve and drops out here.
     */
    static List<String> reconcile(List<String> preferredOrder, Collection<String> actual) {
        List<String> out = new ArrayList<>();
        for (String candidate : preferredOrder) {
            if (actual.contains(candidate) && !out.contains(candidate)) {
                out.add(candidate);
            }
        }
        List<String> remaining = new ArrayList<>(actual);
        java.util.Collections.sort(remaining);
        for (String candidate : remaining) {
            if (!out.contains(candidate)) {
                out.add(candidate);
            }
        }
        return out;
    }
}
