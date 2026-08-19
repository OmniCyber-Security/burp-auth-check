package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import groovy.lang.MissingPropertyException;
import groovy.lang.Script;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The base class every auth script is compiled against.
 *
 * <p>Its only job is to give the bindings real types. At runtime it changes
 * nothing -- each accessor just reads the binding the engine already set. In an
 * editor it is the difference between {@code creds.} offering nothing and
 * {@code http.} listing every helper with its signature, which is why the
 * reference stub in {@code scripts/} points at it.
 *
 * <p>Accessors return empty rather than throwing when a binding is absent, so a
 * script under test in an IDE, or run through the syntax check, behaves
 * predictably.
 */
public abstract class AuthScriptBase extends Script {

    /**
     * This identity's credential variables, as configured on the Identities tab.
     * e.g. {@code creds.username}, {@code creds.password}.
     */
    @SuppressWarnings("unchecked")
    public Map<String, String> getCreds() {
        Object value = lookup("creds");
        return value instanceof Map ? (Map<String, String>) value : new LinkedHashMap<>();
    }

    /** HTTP helper. Requests go through Burp and appear in the Logger. */
    public ScriptHttp getHttp() {
        Object value = lookup("http");
        return value instanceof ScriptHttp http ? http : null;
    }

    /**
     * Scratch space that survives between refreshes of this identity's session.
     * Stash a refresh token here so the next login can reuse it.
     */
    @SuppressWarnings("unchecked")
    public Map<String, String> getVars() {
        Object value = lookup("vars");
        return value instanceof Map ? (Map<String, String>) value : new LinkedHashMap<>();
    }

    /** Progress and diagnostics, shown under the script and in Burp's output. */
    public ScriptLog getLog() {
        Object value = lookup("log");
        return value instanceof ScriptLog log ? log : null;
    }

    /** The full Montoya API, for anything the helper does not cover. */
    public MontoyaApi getApi() {
        Object value = lookup("api");
        return value instanceof MontoyaApi montoya ? montoya : null;
    }

    /** This identity's display name. */
    public String getIdentity() {
        Object value = lookup("identity");
        return value == null ? "" : String.valueOf(value);
    }

    private Object lookup(String name) {
        try {
            return getBinding().getVariable(name);
        } catch (MissingPropertyException e) {
            return null;
        }
    }
}
