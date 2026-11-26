package com.omnicybersecurity.authcheck.auth;

import com.omnicybersecurity.authcheck.util.Patterns;
import com.omnicybersecurity.authcheck.util.Text;

/**
 * Reads a session-check probe's response as "alive" or "not proven alive".
 *
 * <p>The probe does not follow redirects. With a healthy-session pattern the
 * pattern alone decides. Without one only a 2xx counts as alive: a 3xx is the
 * usual way an app sends a dead session to its login page, and reading it as
 * alive would turn a denied replay of a dead session into a false "Enforced".
 * An extra re-auth is the cheaper mistake.
 */
final class SessionLiveness {

    private SessionLiveness() {
    }

    /**
     * @param status       the probe response's status code
     * @param responseText status line, headers and body, as the pattern sees them
     * @param healthyRegex the identity's healthy-session pattern, may be blank
     */
    static boolean isAlive(int status, String responseText, String healthyRegex) {
        if (!Text.isBlank(healthyRegex)) {
            return Patterns.find(healthyRegex, responseText);
        }
        return status >= 200 && status < 300;
    }
}
