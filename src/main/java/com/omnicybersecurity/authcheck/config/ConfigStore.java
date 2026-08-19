package com.omnicybersecurity.authcheck.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.PersistedObject;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads and writes the extension's state -- including every identity's
 * credentials -- into the <em>Burp project</em> via
 * {@code api.persistence().extensionData()}.
 *
 * <p>Credentials live as plain string entries in the project file, so they
 * travel with the project and are reachable by other tooling that opens it.
 * They are not encrypted; the README says so explicitly.
 *
 * <p>Saves rewrite the whole subtree. The tree is assembled detached and
 * attached to the root in one call, which keeps a half-written config from ever
 * being visible.
 */
public final class ConfigStore {

    private static final String ROOT_KEY = "omnicyber.authcheck";
    private static final String IDENTITIES_KEY = "identities";
    private static final String CREDENTIALS_KEY = "credentials";
    private static final String ORDER_KEY = "order";
    /** Credential order lives on the identity node, not among the credentials. */
    private static final String CREDENTIAL_ORDER_KEY = "credentialOrder";

    private final MontoyaApi api;

    public ConfigStore(MontoyaApi api) {
        this.api = api;
    }

    /** True when this project already holds configuration for this extension. */
    public boolean hasStoredConfig() {
        return api.persistence().extensionData().getChildObject(ROOT_KEY) != null;
    }

    // -- load ----------------------------------------------------------------

    public void load(Settings settings, List<Identity> identities) {
        PersistedObject root = api.persistence().extensionData().getChildObject(ROOT_KEY);
        if (root == null) {
            return;
        }
        loadSettings(root, settings);
        loadIdentities(root, identities);
    }

    private void loadSettings(PersistedObject cfg, Settings settings) {
        settings.autoTestEnabled(bool(cfg, "autoTestEnabled", settings.autoTestEnabled()));
        settings.testUnauthenticated(bool(cfg, "testUnauthenticated", settings.testUnauthenticated()));
        settings.onlyInScope(bool(cfg, "onlyInScope", settings.onlyInScope()));
        settings.dedupeRequests(bool(cfg, "dedupeRequests", settings.dedupeRequests()));
        settings.dedupeIncludesParamNames(
                bool(cfg, "dedupeIncludesParamNames", settings.dedupeIncludesParamNames()));
        settings.skipStaticResources(bool(cfg, "skipStaticResources", settings.skipStaticResources()));
        settings.useBurpVariationsAnalyzer(
                bool(cfg, "useBurpVariationsAnalyzer", settings.useBurpVariationsAnalyzer()));
        settings.followRedirectsOnReplay(
                bool(cfg, "followRedirectsOnReplay", settings.followRedirectsOnReplay()));
        settings.treatLoginRedirectAsEnforced(
                bool(cfg, "treatLoginRedirectAsEnforced", settings.treatLoginRedirectAsEnforced()));
        settings.persistResults(bool(cfg, "persistResults", settings.persistResults()));
        settings.persistOnlyInteresting(
                bool(cfg, "persistOnlyInteresting", settings.persistOnlyInteresting()));

        settings.skipExtensions(string(cfg, "skipExtensions", settings.skipExtensions()));
        settings.includeUrlRegex(string(cfg, "includeUrlRegex", settings.includeUrlRegex()));
        settings.excludeUrlRegex(string(cfg, "excludeUrlRegex", settings.excludeUrlRegex()));
        settings.skipStatusCodes(string(cfg, "skipStatusCodes", settings.skipStatusCodes()));
        settings.skipMethods(string(cfg, "skipMethods", settings.skipMethods()));
        settings.resultsSortColumn(string(cfg, "resultsSortColumn", settings.resultsSortColumn()));
        settings.resultsSortAscending(bool(cfg, "resultsSortAscending", settings.resultsSortAscending()));
        settings.deniedStatusCodes(string(cfg, "deniedStatusCodes", settings.deniedStatusCodes()));
        settings.deniedBodyRegex(string(cfg, "deniedBodyRegex", settings.deniedBodyRegex()));
        settings.loginRedirectRegex(string(cfg, "loginRedirectRegex", settings.loginRedirectRegex()));
        settings.unauthStripHeaders(string(cfg, "unauthStripHeaders", settings.unauthStripHeaders()));

        settings.threadCount(integer(cfg, "threadCount", settings.threadCount()));
        settings.queueCapacity(integer(cfg, "queueCapacity", settings.queueCapacity()));
        settings.maxRecords(integer(cfg, "maxRecords", settings.maxRecords()));
        settings.scriptTimeoutSeconds(integer(cfg, "scriptTimeoutSeconds", settings.scriptTimeoutSeconds()));
        settings.sameThresholdPercent(integer(cfg, "sameThresholdPercent", settings.sameThresholdPercent()));
        settings.maxCompareBytes(integer(cfg, "maxCompareBytes", settings.maxCompareBytes()));
        settings.maxPersistedRecords(integer(cfg, "maxPersistedRecords", settings.maxPersistedRecords()));

        Long timeout = cfg.getLong("responseTimeoutMillis");
        if (timeout != null) {
            settings.responseTimeoutMillis(timeout);
        }

        String tools = cfg.getString("sourceTools");
        if (tools != null) {
            Set<ToolType> parsed = EnumSet.noneOf(ToolType.class);
            for (String name : Text.splitList(tools)) {
                try {
                    parsed.add(ToolType.valueOf(name));
                } catch (IllegalArgumentException e) {
                    // Tool renamed or removed in a newer Burp; drop it silently.
                }
            }
            if (!parsed.isEmpty()) {
                settings.sourceTools(parsed);
            }
        }
    }

    private void loadIdentities(PersistedObject cfg, List<Identity> identities) {
        PersistedObject store = cfg.getChildObject(IDENTITIES_KEY);
        if (store == null) {
            return;
        }
        identities.clear();

        // childObjectKeys() is authoritative for which identities exist; the order
        // entry only says how to arrange them, and anything in it that does not
        // resolve to a child is discarded.
        List<String> ids = PersistedLists.reconcile(
                PersistedLists.readOrder(store, ORDER_KEY), store.childObjectKeys());

        for (String id : ids) {
            PersistedObject node = store.getChildObject(id);
            if (node == null) {
                continue;
            }
            Identity identity = new Identity(id, string(node, "name", "(unnamed)"));
            identity.enabled(bool(node, "enabled", true));
            identity.authScript(string(node, "authScript", ""));
            identity.staticHeaders(string(node, "staticHeaders", ""));
            identity.stripHeaders(string(node, "stripHeaders", identity.stripHeaders()));
            identity.tokenHeaderName(string(node, "tokenHeaderName", "Authorization"));
            identity.sessionInvalidRegex(string(node, "sessionInvalidRegex", ""));
            identity.sessionCheckUrl(string(node, "sessionCheckUrl", ""));
            identity.sessionValidRegex(string(node, "sessionValidRegex", ""));
            identity.notes(string(node, "notes", ""));
            identity.reauthOnDenied(bool(node, "reauthOnDenied", true));
            Long refresh = node.getLong("refreshIntervalSeconds");
            identity.refreshIntervalSeconds(refresh == null ? 0L : refresh);

            PersistedObject creds = node.getChildObject(CREDENTIALS_KEY);
            if (creds != null) {
                // stringKeys() has no defined order, so the tester's row order is
                // restored from a separate entry on the identity node -- outside
                // the credential map, so it cannot collide with a credential name.
                Set<String> present = new LinkedHashSet<>(creds.stringKeys());
                present.remove(ORDER_KEY);

                List<String> preferred = PersistedLists.readOrder(node, CREDENTIAL_ORDER_KEY);
                if (preferred.isEmpty()) {
                    preferred = PersistedLists.readOrder(creds, ORDER_KEY);
                }
                for (String key : PersistedLists.reconcile(preferred, present)) {
                    String value = creds.getString(key);
                    if (value != null) {
                        identity.credentials().put(key, value);
                    }
                }
            }
            identities.add(identity);
        }
    }

    // -- save ----------------------------------------------------------------

    public void save(Settings settings, List<Identity> identities) {
        PersistedObject cfg = PersistedObject.persistedObject();

        cfg.setBoolean("autoTestEnabled", settings.autoTestEnabled());
        cfg.setBoolean("testUnauthenticated", settings.testUnauthenticated());
        cfg.setBoolean("onlyInScope", settings.onlyInScope());
        cfg.setBoolean("dedupeRequests", settings.dedupeRequests());
        cfg.setBoolean("dedupeIncludesParamNames", settings.dedupeIncludesParamNames());
        cfg.setBoolean("skipStaticResources", settings.skipStaticResources());
        cfg.setBoolean("useBurpVariationsAnalyzer", settings.useBurpVariationsAnalyzer());
        cfg.setBoolean("followRedirectsOnReplay", settings.followRedirectsOnReplay());
        cfg.setBoolean("treatLoginRedirectAsEnforced", settings.treatLoginRedirectAsEnforced());
        cfg.setBoolean("persistResults", settings.persistResults());
        cfg.setBoolean("persistOnlyInteresting", settings.persistOnlyInteresting());

        cfg.setString("skipExtensions", settings.skipExtensions());
        cfg.setString("includeUrlRegex", settings.includeUrlRegex());
        cfg.setString("excludeUrlRegex", settings.excludeUrlRegex());
        cfg.setString("skipStatusCodes", settings.skipStatusCodes());
        cfg.setString("skipMethods", settings.skipMethods());
        cfg.setString("resultsSortColumn", settings.resultsSortColumn());
        cfg.setBoolean("resultsSortAscending", settings.resultsSortAscending());
        cfg.setString("deniedStatusCodes", settings.deniedStatusCodes());
        cfg.setString("deniedBodyRegex", settings.deniedBodyRegex());
        cfg.setString("loginRedirectRegex", settings.loginRedirectRegex());
        cfg.setString("unauthStripHeaders", settings.unauthStripHeaders());

        cfg.setInteger("threadCount", settings.threadCount());
        cfg.setInteger("queueCapacity", settings.queueCapacity());
        cfg.setInteger("maxRecords", settings.maxRecords());
        cfg.setInteger("scriptTimeoutSeconds", settings.scriptTimeoutSeconds());
        cfg.setInteger("sameThresholdPercent", settings.sameThresholdPercent());
        cfg.setInteger("maxCompareBytes", settings.maxCompareBytes());
        cfg.setInteger("maxPersistedRecords", settings.maxPersistedRecords());
        cfg.setLong("responseTimeoutMillis", settings.responseTimeoutMillis());

        List<String> toolNames = new ArrayList<>();
        for (ToolType tool : settings.sourceTools()) {
            toolNames.add(tool.name());
        }
        cfg.setString("sourceTools", String.join(",", toolNames));

        PersistedObject store = PersistedObject.persistedObject();
        List<String> order = new ArrayList<>();
        for (Identity identity : identities) {
            order.add(identity.id());
            store.setChildObject(identity.id(), toPersisted(identity));
        }
        PersistedLists.writeOrder(store, ORDER_KEY, order);
        cfg.setChildObject(IDENTITIES_KEY, store);

        api.persistence().extensionData().setChildObject(ROOT_KEY, cfg);
    }

    private PersistedObject toPersisted(Identity identity) {
        PersistedObject node = PersistedObject.persistedObject();
        node.setString("name", identity.name());
        node.setString("authScript", identity.authScript());
        node.setString("staticHeaders", identity.staticHeaders());
        node.setString("stripHeaders", identity.stripHeaders());
        node.setString("tokenHeaderName", identity.tokenHeaderName());
        node.setString("sessionInvalidRegex", identity.sessionInvalidRegex());
        node.setString("sessionCheckUrl", identity.sessionCheckUrl());
        node.setString("sessionValidRegex", identity.sessionValidRegex());
        node.setString("notes", identity.notes());
        node.setBoolean("enabled", identity.enabled());
        node.setBoolean("reauthOnDenied", identity.reauthOnDenied());
        node.setLong("refreshIntervalSeconds", identity.refreshIntervalSeconds());

        PersistedObject creds = PersistedObject.persistedObject();
        List<String> credOrder = new ArrayList<>();
        for (Map.Entry<String, String> entry : identity.credentialsSnapshot().entrySet()) {
            if (Text.isBlank(entry.getKey()) || ORDER_KEY.equals(entry.getKey())) {
                continue;
            }
            creds.setString(entry.getKey(), Text.nullToEmpty(entry.getValue()));
            credOrder.add(entry.getKey());
        }
        node.setChildObject(CREDENTIALS_KEY, creds);
        PersistedLists.writeOrder(node, CREDENTIAL_ORDER_KEY, credOrder);
        return node;
    }

    // -- primitives ----------------------------------------------------------

    private static boolean bool(PersistedObject object, String key, boolean fallback) {
        Boolean value = object.getBoolean(key);
        return value == null ? fallback : value;
    }

    private static String string(PersistedObject object, String key, String fallback) {
        String value = object.getString(key);
        return value == null ? fallback : value;
    }

    private static int integer(PersistedObject object, String key, int fallback) {
        Integer value = object.getInteger(key);
        return value == null ? fallback : value;
    }
}
