package com.omnicybersecurity.authcheck.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Issue #29: a redirect to the login page must not read as a live session. */
class SessionLivenessTest {

    private static final String LOGIN_REDIRECT =
            "302 Found\nLocation: https://app.example/login?next=%2Fapi%2Fme\n\n";
    private static final String PROFILE =
            "200 OK\nContent-Type: application/json\n\n{\"email\": \"a@example.com\"}";

    @Test
    void withoutAPatternA2xxIsAlive() {
        assertTrue(SessionLiveness.isAlive(200, PROFILE, ""));
        assertTrue(SessionLiveness.isAlive(204, "204 No Content\n\n", null));
    }

    @Test
    void withoutAPatternARedirectIsNotProvenAlive() {
        assertFalse(SessionLiveness.isAlive(302, LOGIN_REDIRECT, ""));
        assertFalse(SessionLiveness.isAlive(301, "301 Moved\nLocation: /home\n\n", "  "));
        assertFalse(SessionLiveness.isAlive(303, "303 See Other\n\n", null));
        assertFalse(SessionLiveness.isAlive(307, "307 Temporary Redirect\n\n", ""));
    }

    @Test
    void withoutAPatternErrorsAreDead() {
        assertFalse(SessionLiveness.isAlive(401, "401 Unauthorized\n\n", ""));
        assertFalse(SessionLiveness.isAlive(500, "500 Internal Server Error\n\n", ""));
    }

    @Test
    void aPatternDecidesRegardlessOfStatus() {
        String email = "\"email\"\\s*:";
        assertTrue(SessionLiveness.isAlive(200, PROFILE, email));
        assertFalse(SessionLiveness.isAlive(200, "200 OK\n\n<form id=login>", email));
        assertFalse(SessionLiveness.isAlive(302, LOGIN_REDIRECT, email));
        // An app that redirects live sessions on can still be described with a pattern.
        assertTrue(SessionLiveness.isAlive(302, "302 Found\nLocation: /dashboard\n\n",
                "(?i)location: /dashboard"));
    }
}
