package com.omnicybersecurity.authcheck.util;

import java.io.InputStream;
import java.util.jar.Manifest;

/**
 * Which build is actually loaded.
 *
 * <p>Debugging "the replay is missing a header" is guesswork without knowing
 * whether the running jar predates the fix for it, so the build stamps its
 * version and commit into the manifest and the extension logs them on load.
 */
public final class BuildInfo {

    private static final String UNKNOWN = "unknown";

    private static String version = UNKNOWN;
    private static String commit = UNKNOWN;

    static {
        try (InputStream in = BuildInfo.class.getResourceAsStream("/META-INF/MANIFEST.MF")) {
            if (in != null) {
                Manifest manifest = new Manifest(in);
                String title = manifest.getMainAttributes().getValue("Implementation-Title");
                // Another jar's manifest could be first on the classpath; only
                // trust one that identifies itself as ours.
                if ("Burp Auth Check".equals(title)) {
                    version = orUnknown(manifest.getMainAttributes().getValue("Implementation-Version"));
                    commit = orUnknown(manifest.getMainAttributes().getValue("Implementation-Commit"));
                }
            }
        } catch (Exception e) {
            // A missing or unreadable manifest just means "unknown".
        }
    }

    private BuildInfo() {
    }

    public static String version() {
        return version;
    }

    public static String commit() {
        return commit;
    }

    /** e.g. {@code 1.0.0 (0de4774)}. */
    public static String describe() {
        return version + " (" + commit + ")";
    }

    private static String orUnknown(String value) {
        return Text.isBlank(value) ? UNKNOWN : value;
    }
}
