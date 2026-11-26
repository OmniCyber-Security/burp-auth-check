package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionPatternMatchingTest {

    private static final String BEARER_PATTERN = "WWW-Authenticate: Bearer error=\"invalid_token\"";

    private static HttpResponse http2Expired() {
        // HTTP/2 header names arrive lower-case.
        return FakeHttp.response(401, "", Map.of("www-authenticate", "Bearer error=\"invalid_token\""));
    }

    @Test
    void titleCaseHeaderPatternMatchesHttp2LowerCaseName() {
        assertTrue(SessionManager.matchesResponse(BEARER_PATTERN, http2Expired()));
    }

    @Test
    void titleCaseHeaderPatternStillMatchesHttp1Name() {
        HttpResponse http1 = FakeHttp.response(401, "",
                Map.of("WWW-Authenticate", "Bearer error=\"invalid_token\""));
        assertTrue(SessionManager.matchesResponse(BEARER_PATTERN, http1));
    }

    @Test
    void explicitCaseInsensitiveFlagStillWorks() {
        assertTrue(SessionManager.matchesResponse(
                "(?i)www-authenticate: bearer error=\"invalid_token\"", http2Expired()));
        assertTrue(SessionManager.matchesResponse(
                "(?i)your session has expired", FakeHttp.response(200, "Your Session Has Expired")));
    }

    @Test
    void bodyMatchingStaysCaseSensitive() {
        HttpResponse response = FakeHttp.response(200, "Your session has expired");
        assertTrue(SessionManager.matchesResponse("session has expired", response));
        assertFalse(SessionManager.matchesResponse("Session Has Expired", response));
    }

    @Test
    void healthyHttp2ResponseDoesNotMatch() {
        HttpResponse healthy = FakeHttp.response(200, "{\"ok\":true}", Map.of("content-type", "application/json"));
        assertFalse(SessionManager.matchesResponse(BEARER_PATTERN, healthy));
    }

    @Test
    void patternSpanningHeadersAndBodyStillMatches() {
        HttpResponse response = FakeHttp.response(401, "denied", Map.of("X-Reason", "expired"));
        assertTrue(SessionManager.matchesResponse("(?s)X-Reason: expired.*denied", response));
    }
}
