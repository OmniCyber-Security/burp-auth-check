package com.omnicybersecurity.authcheck.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** One tested request: the baseline exchange plus every identity's replay. */
public final class AuthTestRecord {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final int index;
    private final LocalDateTime timestamp;
    private final String source;
    private final HttpRequestResponse baseline;
    private final Map<String, VariantResult> results;
    private final boolean publicEndpoint;
    private final String note;

    public AuthTestRecord(int index, String source, HttpRequestResponse baseline,
            Map<String, VariantResult> results, boolean publicEndpoint, String note) {
        this(index, LocalDateTime.now(), source, baseline, results, publicEndpoint, note);
    }

    /** Rebuilds a record read back from the project, keeping its original time. */
    public AuthTestRecord(int index, LocalDateTime timestamp, String source, HttpRequestResponse baseline,
            Map<String, VariantResult> results, boolean publicEndpoint, String note) {
        this.index = index;
        this.timestamp = timestamp;
        this.source = source;
        this.baseline = baseline;
        this.results = Collections.unmodifiableMap(new LinkedHashMap<>(results));
        this.publicEndpoint = publicEndpoint;
        this.note = note == null ? "" : note;
    }

    public int index() {
        return index;
    }

    public String time() {
        return timestamp.format(TIME);
    }

    public LocalDateTime timestamp() {
        return timestamp;
    }

    public String source() {
        return source;
    }

    public HttpRequestResponse baseline() {
        return baseline;
    }

    public Map<String, VariantResult> results() {
        return results;
    }

    public VariantResult result(String variantKey) {
        return results.get(variantKey);
    }

    /** True when the unauthenticated replay also succeeded -- nothing to protect. */
    public boolean publicEndpoint() {
        return publicEndpoint;
    }

    public String note() {
        return note;
    }

    public String method() {
        return baseline.request().method();
    }

    public String url() {
        return baseline.request().url();
    }

    public String host() {
        return baseline.request().httpService().host();
    }

    public short baselineStatus() {
        return baseline.hasResponse() ? baseline.response().statusCode() : (short) 0;
    }

    public int baselineLength() {
        return baseline.hasResponse() ? baseline.response().body().length() : 0;
    }

    /** Worst verdict across all variants, for sorting and at-a-glance triage. */
    public Verdict worstVerdict() {
        Verdict worst = Verdict.NOT_TESTED;
        for (VariantResult result : results.values()) {
            if (result.verdict().severity() > worst.severity()) {
                worst = result.verdict();
            }
        }
        return worst;
    }

    public boolean hasFinding() {
        return results.values().stream().anyMatch(r -> r.verdict().isFinding());
    }
}
