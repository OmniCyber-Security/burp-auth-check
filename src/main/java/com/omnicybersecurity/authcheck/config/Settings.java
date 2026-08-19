package com.omnicybersecurity.authcheck.config;

import burp.api.montoya.core.ToolType;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Extension-wide settings. Fields are volatile because the UI writes them on the
 * event thread while engine workers read them per request.
 */
public final class Settings {

    /** Tools whose traffic may be auto-tested. EXTENSIONS is never allowed. */
    public static final List<ToolType> SELECTABLE_TOOLS = List.of(
            ToolType.PROXY, ToolType.REPEATER, ToolType.SCANNER, ToolType.INTRUDER,
            ToolType.TARGET, ToolType.LOGGER, ToolType.ORGANIZER);

    private volatile boolean autoTestEnabled = false;
    private volatile boolean testUnauthenticated = true;
    private volatile boolean onlyInScope = true;
    private volatile boolean dedupeRequests = true;
    private volatile boolean dedupeIncludesParamNames = true;
    private volatile boolean skipStaticResources = true;

    private volatile Set<ToolType> sourceTools = EnumSet.of(ToolType.PROXY, ToolType.REPEATER);

    private volatile String skipExtensions =
            "css, js, mjs, map, png, jpg, jpeg, gif, svg, ico, webp, avif, woff, woff2, ttf, eot, mp4, mp3, pdf";
    private volatile String includeUrlRegex = "";
    private volatile String excludeUrlRegex = "";
    private volatile String skipStatusCodes = "301, 302, 304, 404";

    private volatile int threadCount = 4;
    private volatile int queueCapacity = 500;
    private volatile long responseTimeoutMillis = 20_000L;
    private volatile int maxRecords = 2_000;
    private volatile int scriptTimeoutSeconds = 30;

    // -- storing results in the project file --------------------------------

    private volatile boolean persistResults = true;
    private volatile boolean persistOnlyInteresting = false;
    private volatile int maxPersistedRecords = 500;

    // -- response comparison -------------------------------------------------

    private volatile int sameThresholdPercent = 95;
    private volatile int maxCompareBytes = 262_144;
    private volatile boolean useBurpVariationsAnalyzer = false;
    private volatile boolean followRedirectsOnReplay = false;

    // -- what "denied" looks like -------------------------------------------

    private volatile String deniedStatusCodes = "401, 403";
    private volatile String deniedBodyRegex =
            "(?i)(access[ _-]?denied|unauthori[sz]ed|not[ _-]authori[sz]ed|permission[ _-]denied"
            + "|forbidden|must be logged in|invalid[ _-]token|token[ _-]expired|session[ _-]expired)";
    private volatile boolean treatLoginRedirectAsEnforced = true;
    private volatile String loginRedirectRegex = "(?i)(/login|/signin|/sign-in|/auth/|/account/login|/session/new)";

    // -- unauthenticated variant --------------------------------------------

    private volatile String unauthStripHeaders =
            "Authorization, Proxy-Authorization, Cookie, X-Api-Key, Api-Key, X-Auth-Token, "
            + "X-Access-Token, X-Session-Token, X-CSRF-Token, X-XSRF-Token";

    // -- accessors -----------------------------------------------------------

    public boolean autoTestEnabled() {
        return autoTestEnabled;
    }

    public void autoTestEnabled(boolean value) {
        this.autoTestEnabled = value;
    }

    public boolean testUnauthenticated() {
        return testUnauthenticated;
    }

    public void testUnauthenticated(boolean value) {
        this.testUnauthenticated = value;
    }

    public boolean onlyInScope() {
        return onlyInScope;
    }

    public void onlyInScope(boolean value) {
        this.onlyInScope = value;
    }

    public boolean dedupeRequests() {
        return dedupeRequests;
    }

    public void dedupeRequests(boolean value) {
        this.dedupeRequests = value;
    }

    public boolean dedupeIncludesParamNames() {
        return dedupeIncludesParamNames;
    }

    public void dedupeIncludesParamNames(boolean value) {
        this.dedupeIncludesParamNames = value;
    }

    public boolean skipStaticResources() {
        return skipStaticResources;
    }

    public void skipStaticResources(boolean value) {
        this.skipStaticResources = value;
    }

    public Set<ToolType> sourceTools() {
        return sourceTools;
    }

    public void sourceTools(Set<ToolType> tools) {
        EnumSet<ToolType> copy = EnumSet.noneOf(ToolType.class);
        copy.addAll(tools);
        // Replaying through api.http() surfaces as EXTENSIONS; allowing it here
        // would make the extension test its own traffic forever.
        copy.remove(ToolType.EXTENSIONS);
        this.sourceTools = copy;
    }

    public String skipExtensions() {
        return skipExtensions;
    }

    public void skipExtensions(String value) {
        this.skipExtensions = Text.nullToEmpty(value);
    }

    public String includeUrlRegex() {
        return includeUrlRegex;
    }

    public void includeUrlRegex(String value) {
        this.includeUrlRegex = Text.nullToEmpty(value);
    }

    public String excludeUrlRegex() {
        return excludeUrlRegex;
    }

    public void excludeUrlRegex(String value) {
        this.excludeUrlRegex = Text.nullToEmpty(value);
    }

    public String skipStatusCodes() {
        return skipStatusCodes;
    }

    public void skipStatusCodes(String value) {
        this.skipStatusCodes = Text.nullToEmpty(value);
    }

    public int threadCount() {
        return threadCount;
    }

    public void threadCount(int value) {
        this.threadCount = Math.max(1, Math.min(32, value));
    }

    public int queueCapacity() {
        return queueCapacity;
    }

    public void queueCapacity(int value) {
        this.queueCapacity = Math.max(10, value);
    }

    public long responseTimeoutMillis() {
        return responseTimeoutMillis;
    }

    public void responseTimeoutMillis(long value) {
        this.responseTimeoutMillis = Math.max(1_000L, value);
    }

    public int maxRecords() {
        return maxRecords;
    }

    public void maxRecords(int value) {
        this.maxRecords = Math.max(50, value);
    }

    public int scriptTimeoutSeconds() {
        return scriptTimeoutSeconds;
    }

    public void scriptTimeoutSeconds(int value) {
        this.scriptTimeoutSeconds = Math.max(1, value);
    }

    /** Whether tested requests and responses are written into the Burp project. */
    public boolean persistResults() {
        return persistResults;
    }

    public void persistResults(boolean value) {
        this.persistResults = value;
    }

    /** Store only rows worth revisiting, rather than every enforced result. */
    public boolean persistOnlyInteresting() {
        return persistOnlyInteresting;
    }

    public void persistOnlyInteresting(boolean value) {
        this.persistOnlyInteresting = value;
    }

    /** Cap on stored results, independent of how many are held in memory. */
    public int maxPersistedRecords() {
        return maxPersistedRecords;
    }

    public void maxPersistedRecords(int value) {
        this.maxPersistedRecords = Math.max(0, value);
    }

    public int sameThresholdPercent() {
        return sameThresholdPercent;
    }

    public void sameThresholdPercent(int value) {
        this.sameThresholdPercent = Math.max(1, Math.min(100, value));
    }

    public int maxCompareBytes() {
        return maxCompareBytes;
    }

    public void maxCompareBytes(int value) {
        this.maxCompareBytes = Math.max(1_024, value);
    }

    public boolean useBurpVariationsAnalyzer() {
        return useBurpVariationsAnalyzer;
    }

    public void useBurpVariationsAnalyzer(boolean value) {
        this.useBurpVariationsAnalyzer = value;
    }

    public boolean followRedirectsOnReplay() {
        return followRedirectsOnReplay;
    }

    public void followRedirectsOnReplay(boolean value) {
        this.followRedirectsOnReplay = value;
    }

    public String deniedStatusCodes() {
        return deniedStatusCodes;
    }

    public void deniedStatusCodes(String value) {
        this.deniedStatusCodes = Text.nullToEmpty(value);
    }

    public String deniedBodyRegex() {
        return deniedBodyRegex;
    }

    public void deniedBodyRegex(String value) {
        this.deniedBodyRegex = Text.nullToEmpty(value);
    }

    public boolean treatLoginRedirectAsEnforced() {
        return treatLoginRedirectAsEnforced;
    }

    public void treatLoginRedirectAsEnforced(boolean value) {
        this.treatLoginRedirectAsEnforced = value;
    }

    public String loginRedirectRegex() {
        return loginRedirectRegex;
    }

    public void loginRedirectRegex(String value) {
        this.loginRedirectRegex = Text.nullToEmpty(value);
    }

    public String unauthStripHeaders() {
        return unauthStripHeaders;
    }

    public void unauthStripHeaders(String value) {
        this.unauthStripHeaders = Text.nullToEmpty(value);
    }
}
