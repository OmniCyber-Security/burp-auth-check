package com.omnicybersecurity.authcheck.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * The outcome of replaying one request as one identity.
 *
 * @param variantKey identity id, or {@link Identity#UNAUTHENTICATED_KEY}
 * @param label      display name of the identity
 * @param verdict    conclusion drawn by the analyser
 * @param similarity 0..1 body similarity against the baseline response
 * @param detail     human-readable explanation of the verdict
 * @param reAuthed   true when the session had to be rebuilt mid-test
 * @param exchange   the replayed request/response, or null on error
 */
public record VariantResult(
        String variantKey,
        String label,
        Verdict verdict,
        double similarity,
        String detail,
        boolean reAuthed,
        HttpRequestResponse exchange) {

    public static VariantResult failed(String variantKey, String label, Verdict verdict, String detail) {
        return new VariantResult(variantKey, label, verdict, 0d, detail, false, null);
    }

    public boolean isUnauthenticated() {
        return Identity.UNAUTHENTICATED_KEY.equals(variantKey);
    }

    public String similarityPercent() {
        return exchange == null ? "" : Math.round(similarity * 100) + "%";
    }
}
