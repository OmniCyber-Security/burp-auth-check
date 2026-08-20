package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import groovy.lang.Closure;
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

    /** Free text. */
    public static final ScriptParam.Type STRING = ScriptParam.Type.STRING;
    /** Free text, masked in the UI and never shown by accident. */
    public static final ScriptParam.Type SECRET = ScriptParam.Type.SECRET;
    /** Whole number. */
    public static final ScriptParam.Type INT = ScriptParam.Type.INT;
    /** True or false, shown as a checkbox. */
    public static final ScriptParam.Type BOOL = ScriptParam.Type.BOOL;
    /** Absolute URL, e.g. a base address. */
    public static final ScriptParam.Type URL = ScriptParam.Type.URL;
    /** One of a fixed set of values, shown as a drop-down. */
    public static final ScriptParam.Type CHOICE = ScriptParam.Type.CHOICE;
    /** Multi-line text, e.g. a PEM key. */
    public static final ScriptParam.Type TEXT = ScriptParam.Type.TEXT;

    /**
     * Declares the credential variables this script reads, so the Identities tab
     * can render them as a form with labels, types and help instead of leaving
     * the tester to guess the names out of a comment.
     *
     * <pre>
     * params {
     *     param 'base',     type: URL,    required: true, label: 'Base URL'
     *     param 'username', type: STRING, required: true
     *     param 'password', type: SECRET, required: true
     *     param 'scope',    type: STRING, defaultValue: 'openid profile',
     *           help: 'Scopes requested at the token endpoint'
     * }
     * </pre>
     *
     * <p>A param is optional unless {@code required: true}, and a
     * {@code defaultValue} makes it optional by definition -- the engine fills
     * it in when the field is left blank, so the script can just read
     * {@code creds.scope}.
     *
     * <p>Declaring is optional: a script without a params block gets the
     * free-form name/value table, exactly as before.
     *
     * <p>At runtime this does nothing. The block is read straight from the
     * source before the script runs, by {@link ScriptParamExtractor}, which is
     * what lets the form exist before any credential has been entered.
     */
    public void params(Closure<?> declaration) {
        // Deliberately empty -- see the javadoc. The declaration is read
        // statically; executing it here would be too late to be useful and would
        // mean a script had to run before its own form could be drawn.
    }

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
