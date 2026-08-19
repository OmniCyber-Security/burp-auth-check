package com.omnicybersecurity.authcheck.model;

import com.omnicybersecurity.authcheck.util.Text;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * One test persona -- "user 1", "user 2", "admin". Holds the credentials
 * (persisted in the Burp project), the Groovy script that turns those
 * credentials into a live session, and the rules for noticing when that session
 * has died.
 *
 * <p>Instances are edited on the Swing event thread and read by engine worker
 * threads, so the mutable fields are volatile.
 */
public final class Identity {

    /** Key used for the built-in unauthenticated pseudo-identity. */
    public static final String UNAUTHENTICATED_KEY = " unauthenticated";

    private final String id;

    private volatile String name;
    private volatile boolean enabled = true;
    private volatile String authScript = "";
    private volatile String staticHeaders = "";
    private volatile String stripHeaders =
            "Authorization, Cookie, X-CSRF-Token, X-XSRF-Token, X-Auth-Token, X-Api-Key";
    private volatile String tokenHeaderName = "Authorization";
    private volatile long refreshIntervalSeconds = 0L;
    private volatile String sessionInvalidRegex = "";
    private volatile boolean reauthOnDenied = true;
    private volatile String sessionCheckUrl = "";
    private volatile String sessionValidRegex = "";
    private volatile String notes = "";

    /** Credentials, kept in insertion order for a stable UI. */
    private final Map<String, String> credentials = new LinkedHashMap<>();

    public Identity(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public static Identity createNew(String name) {
        Identity identity = new Identity(UUID.randomUUID().toString(), name);
        identity.credentials.put("username", "");
        identity.credentials.put("password", "");
        return identity;
    }

    public String id() {
        return id;
    }

    public String name() {
        return name;
    }

    public void name(String value) {
        this.name = Text.isBlank(value) ? "(unnamed)" : value.trim();
    }

    public boolean enabled() {
        return enabled;
    }

    public void enabled(boolean value) {
        this.enabled = value;
    }

    public String authScript() {
        return authScript;
    }

    public void authScript(String value) {
        this.authScript = Text.nullToEmpty(value);
    }

    public boolean hasScript() {
        return !Text.isBlank(authScript);
    }

    /** Extra headers forced onto every request for this identity, one per line. */
    public String staticHeaders() {
        return staticHeaders;
    }

    public void staticHeaders(String value) {
        this.staticHeaders = Text.nullToEmpty(value);
    }

    public Map<String, String> staticHeaderMap() {
        return Text.parseHeaderLines(staticHeaders);
    }

    /** Headers stripped from the base request before this identity's are applied. */
    public String stripHeaders() {
        return stripHeaders;
    }

    public void stripHeaders(String value) {
        this.stripHeaders = Text.nullToEmpty(value);
    }

    /** Header a script's bare-String return value is written to. */
    public String tokenHeaderName() {
        return Text.isBlank(tokenHeaderName) ? "Authorization" : tokenHeaderName.trim();
    }

    public void tokenHeaderName(String value) {
        this.tokenHeaderName = Text.nullToEmpty(value);
    }

    /** Proactive re-auth interval; 0 disables time-based refresh. */
    public long refreshIntervalSeconds() {
        return refreshIntervalSeconds;
    }

    public void refreshIntervalSeconds(long value) {
        this.refreshIntervalSeconds = Math.max(0L, value);
    }

    /**
     * Regex that, when found in a replayed response, means this identity's
     * session has expired. The strongest and cheapest death signal available.
     */
    public String sessionInvalidRegex() {
        return sessionInvalidRegex;
    }

    public void sessionInvalidRegex(String value) {
        this.sessionInvalidRegex = Text.nullToEmpty(value);
    }

    /**
     * When a replay is denied, probe the session-check URL before concluding the
     * session died -- a denial is the expected result of a passing auth check.
     */
    public boolean reauthOnDenied() {
        return reauthOnDenied;
    }

    public void reauthOnDenied(boolean value) {
        this.reauthOnDenied = value;
    }

    /** Cheap authenticated endpoint used to prove the session is still alive. */
    public String sessionCheckUrl() {
        return sessionCheckUrl;
    }

    public void sessionCheckUrl(String value) {
        this.sessionCheckUrl = Text.nullToEmpty(value);
    }

    /** Regex expected in a healthy session-check response. */
    public String sessionValidRegex() {
        return sessionValidRegex;
    }

    public void sessionValidRegex(String value) {
        this.sessionValidRegex = Text.nullToEmpty(value);
    }

    public String notes() {
        return notes;
    }

    public void notes(String value) {
        this.notes = Text.nullToEmpty(value);
    }

    /** Live credential map. Mutated only from the UI thread. */
    public Map<String, String> credentials() {
        return credentials;
    }

    public Map<String, String> credentialsSnapshot() {
        synchronized (credentials) {
            return new LinkedHashMap<>(credentials);
        }
    }

    public Identity duplicate() {
        Identity copy = new Identity(UUID.randomUUID().toString(), name + " (copy)");
        copy.enabled = enabled;
        copy.authScript = authScript;
        copy.staticHeaders = staticHeaders;
        copy.stripHeaders = stripHeaders;
        copy.tokenHeaderName = tokenHeaderName;
        copy.refreshIntervalSeconds = refreshIntervalSeconds;
        copy.sessionInvalidRegex = sessionInvalidRegex;
        copy.reauthOnDenied = reauthOnDenied;
        copy.sessionCheckUrl = sessionCheckUrl;
        copy.sessionValidRegex = sessionValidRegex;
        copy.notes = notes;
        copy.credentials.putAll(credentialsSnapshot());
        return copy;
    }

    @Override
    public String toString() {
        return name;
    }
}
