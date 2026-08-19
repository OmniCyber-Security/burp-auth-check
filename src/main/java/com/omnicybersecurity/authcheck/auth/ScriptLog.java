package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.logging.Logging;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * The {@code log} binding handed to auth scripts. Lines go to Burp's extension
 * output and are also buffered so the Identities panel can show exactly what the
 * last authentication attempt did.
 */
public final class ScriptLog {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    private static final int MAX_BUFFER = 64_000;

    private final Logging logging;
    private final String identityName;
    private final StringBuilder buffer = new StringBuilder();

    public ScriptLog(Logging logging, String identityName) {
        this.logging = logging;
        this.identityName = identityName;
    }

    public void info(Object message) {
        append("INFO ", message);
    }

    public void warn(Object message) {
        append("WARN ", message);
    }

    public void error(Object message) {
        append("ERROR", message);
    }

    /** Groovy's {@code println} inside a script routes here. */
    public void println(Object message) {
        info(message);
    }

    private void append(String level, Object message) {
        String line = LocalTime.now().format(TIME) + "  " + level + "  " + message;
        synchronized (buffer) {
            if (buffer.length() < MAX_BUFFER) {
                buffer.append(line).append('\n');
            }
        }
        logging.logToOutput("[auth-check][" + identityName + "] " + message);
    }

    public String text() {
        synchronized (buffer) {
            return buffer.toString();
        }
    }
}
