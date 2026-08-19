package com.omnicybersecurity.authcheck.model;

/** The conclusion drawn for one identity's replay of one request. */
public enum Verdict {

    /** The identity got the same successful response as the baseline user. */
    BYPASSED("Bypassed!", 4),
    /** Different from baseline, but not recognisably a denial -- needs eyes. */
    NEEDS_REVIEW("Review", 3),
    /** The server refused the identity: authorisation is being enforced. */
    ENFORCED("Enforced", 1),
    /** The identity's session could not be established, so nothing was proven. */
    AUTH_FAILED("Auth failed", 2),
    /** The replay itself failed (connection error, timeout, ...). */
    ERROR("Error", 2),
    /** Filtered out or not run. */
    NOT_TESTED("-", 0);

    private final String label;
    private final int severity;

    Verdict(String label, int severity) {
        this.label = label;
        this.severity = severity;
    }

    public String label() {
        return label;
    }

    public int severity() {
        return severity;
    }

    /** True for verdicts a tester should actively look at. */
    public boolean isFinding() {
        return this == BYPASSED;
    }
}
