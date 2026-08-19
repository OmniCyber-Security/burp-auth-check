package com.omnicybersecurity.authcheck.config;

import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Text;
import groovy.json.JsonOutput;
import groovy.json.JsonSlurper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Reads and writes identities as a file.
 *
 * <p>Project storage is addressed by the extension name, which makes it possible
 * to lose sight of an entire configuration through nothing worse than a rename.
 * A file export is recovery that does not depend on any of that, and it is how
 * an identity set moves between projects or between testers.
 */
public final class IdentityTransfer {

    private static final int FORMAT_VERSION = 1;

    private IdentityTransfer() {
    }

    public static String toJson(List<Identity> identities) {
        List<Map<String, Object>> exported = new ArrayList<>();
        for (Identity identity : identities) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", identity.name());
            entry.put("enabled", identity.enabled());
            entry.put("notes", identity.notes());
            entry.put("credentials", identity.credentialsSnapshot());
            entry.put("authScript", identity.authScript());
            entry.put("staticHeaders", identity.staticHeaders());
            entry.put("stripHeaders", identity.stripHeaders());
            entry.put("tokenHeaderName", identity.tokenHeaderName());
            entry.put("refreshIntervalSeconds", identity.refreshIntervalSeconds());
            entry.put("sessionInvalidRegex", identity.sessionInvalidRegex());
            entry.put("reauthOnDenied", identity.reauthOnDenied());
            entry.put("sessionCheckUrl", identity.sessionCheckUrl());
            entry.put("sessionValidRegex", identity.sessionValidRegex());
            exported.add(entry);
        }

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("format", FORMAT_VERSION);
        document.put("note", "Contains credentials in clear text. Treat as sensitive.");
        document.put("identities", exported);
        return JsonOutput.prettyPrint(JsonOutput.toJson(document));
    }

    /**
     * @param json an export produced by {@link #toJson}
     * @return the identities, each with a fresh id so importing never collides
     *         with an identity already in the project
     */
    @SuppressWarnings("unchecked")
    public static List<Identity> fromJson(String json) {
        Object parsed = new JsonSlurper().parseText(Text.nullToEmpty(json));
        if (!(parsed instanceof Map<?, ?> document)) {
            throw new IllegalArgumentException("Not an identity export: expected a JSON object");
        }
        Object entries = document.get("identities");
        if (!(entries instanceof List<?> list)) {
            throw new IllegalArgumentException("Not an identity export: no 'identities' array");
        }

        List<Identity> imported = new ArrayList<>();
        for (Object element : list) {
            if (!(element instanceof Map<?, ?> entry)) {
                continue;
            }
            Identity identity = new Identity(UUID.randomUUID().toString(),
                    string(entry, "name", "(imported)"));
            identity.enabled(bool(entry, "enabled", true));
            identity.notes(string(entry, "notes", ""));
            identity.authScript(string(entry, "authScript", ""));
            identity.staticHeaders(string(entry, "staticHeaders", ""));
            identity.stripHeaders(string(entry, "stripHeaders", identity.stripHeaders()));
            identity.tokenHeaderName(string(entry, "tokenHeaderName", "Authorization"));
            identity.sessionInvalidRegex(string(entry, "sessionInvalidRegex", ""));
            identity.reauthOnDenied(bool(entry, "reauthOnDenied", true));
            identity.sessionCheckUrl(string(entry, "sessionCheckUrl", ""));
            identity.sessionValidRegex(string(entry, "sessionValidRegex", ""));

            Object refresh = entry.get("refreshIntervalSeconds");
            if (refresh instanceof Number number) {
                identity.refreshIntervalSeconds(number.longValue());
            }

            Object credentials = entry.get("credentials");
            if (credentials instanceof Map<?, ?> map) {
                map.forEach((key, value) -> identity.credentials()
                        .put(String.valueOf(key), value == null ? "" : String.valueOf(value)));
            }
            imported.add(identity);
        }
        if (imported.isEmpty()) {
            throw new IllegalArgumentException("The file contained no identities");
        }
        return imported;
    }

    private static String string(Map<?, ?> map, String key, String fallback) {
        Object value = map.get(key);
        return value == null ? fallback : String.valueOf(value);
    }

    private static boolean bool(Map<?, ?> map, String key, boolean fallback) {
        Object value = map.get(key);
        return value instanceof Boolean flag ? flag : fallback;
    }
}
