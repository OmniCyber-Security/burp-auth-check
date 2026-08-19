package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnicybersecurity.authcheck.model.AuthMaterial;

import java.util.List;

/**
 * Result of one authentication attempt.
 *
 * @param success    whether usable auth material was produced
 * @param material   the auth material (empty when {@code success} is false)
 * @param log        everything the script logged, for display in the UI
 * @param error      failure description, or null on success
 * @param transcript every request the auth script sent and what came back, so the
 *                   login flow can be reviewed and kept in the project next to the
 *                   script that produced it
 */
public record AuthOutcome(
        boolean success,
        AuthMaterial material,
        String log,
        String error,
        List<HttpRequestResponse> transcript) {

    public AuthOutcome(boolean success, AuthMaterial material, String log, String error) {
        this(success, material, log, error, List.of());
    }

    public AuthOutcome withTranscript(List<HttpRequestResponse> exchanges) {
        return new AuthOutcome(success, material, log, error, List.copyOf(exchanges));
    }
}
