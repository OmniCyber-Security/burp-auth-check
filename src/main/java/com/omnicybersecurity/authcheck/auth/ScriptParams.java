package com.omnicybersecurity.authcheck.auth;

import com.omnicybersecurity.authcheck.util.Text;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything one script declares about its credential variables, plus anything
 * wrong with the declaration itself.
 *
 * <p>{@code declared} distinguishes "this script has no params block" from
 * "this script declares nothing": the first keeps the free-form credential
 * table, which is how every script written before this feature carries on
 * working.
 *
 * <p>The checks live here rather than in the UI because the engine runs them
 * too -- the tester should see a missing credential in the form, but a run
 * started from a session-handling rule has to fail the same way for the same
 * reason.
 *
 * @param declared whether the source contained a {@code params} block at all
 * @param params   the declarations, in source order
 * @param problems mistakes in the declaration itself, e.g. an unknown type
 */
public record ScriptParams(boolean declared, List<ScriptParam> params, List<String> problems) {

    private static final ScriptParams NONE = new ScriptParams(false, List.of(), List.of());

    public ScriptParams {
        params = params == null ? List.of() : List.copyOf(params);
        problems = problems == null ? List.of() : List.copyOf(problems);
    }

    /** A script that declares nothing, so the tester keeps the free-form table. */
    public static ScriptParams none() {
        return NONE;
    }

    public boolean isEmpty() {
        return params.isEmpty();
    }

    /** True when there are declared fields to render a form from. */
    public boolean hasFields() {
        return declared && !params.isEmpty();
    }

    public ScriptParam find(String name) {
        for (ScriptParam param : params) {
            if (param.name().equals(name)) {
                return param;
            }
        }
        return null;
    }

    public boolean declares(String name) {
        return find(name) != null;
    }

    /**
     * The credentials a script actually sees: what the tester typed, with any
     * declared default filling in for a field left blank.
     */
    public Map<String, String> withDefaults(Map<String, String> credentials) {
        Map<String, String> effective = new LinkedHashMap<>(credentials);
        for (ScriptParam param : params) {
            if (param.hasDefault() && Text.isBlank(effective.get(param.name()))) {
                effective.put(param.name(), param.defaultValue());
            }
        }
        return effective;
    }

    /** Names that would fall back to their default, for the script log. */
    public List<String> defaulted(Map<String, String> credentials) {
        List<String> names = new ArrayList<>();
        for (ScriptParam param : params) {
            if (param.hasDefault() && Text.isBlank(credentials.get(param.name()))) {
                names.add(param.name());
            }
        }
        return names;
    }

    /** Required fields with nothing in them. */
    public List<String> missingRequired(Map<String, String> credentials) {
        List<String> missing = new ArrayList<>();
        for (ScriptParam param : params) {
            if (param.required() && Text.isBlank(credentials.get(param.name()))) {
                missing.add(param.name());
            }
        }
        return missing;
    }

    /** Filled-in fields whose value does not fit the declared type. */
    public List<String> valueProblems(Map<String, String> credentials) {
        List<String> problems = new ArrayList<>();
        for (ScriptParam param : params) {
            String problem = param.problemWith(credentials.get(param.name()));
            if (problem != null) {
                problems.add(param.name() + " " + problem);
            }
        }
        return problems;
    }
}
