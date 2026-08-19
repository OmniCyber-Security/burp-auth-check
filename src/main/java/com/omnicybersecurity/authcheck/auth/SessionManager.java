package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.engine.RequestMutator;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Patterns;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Owns each identity's live session.
 *
 * <p>This is the part that makes the extension usable against applications whose
 * sessions die in minutes. Three mechanisms cooperate:
 * <ol>
 *   <li><b>Proactive refresh</b> -- a background ticker re-runs the auth script
 *       before the identity's configured lifetime elapses, so sessions stay warm
 *       even while the tester is idle.</li>
 *   <li><b>Definitive death signal</b> -- the identity's
 *       {@code sessionInvalidRegex} matched in a replayed response means the
 *       session is gone; re-authenticate and replay once.</li>
 *   <li><b>Denial disambiguation</b> -- a 401/403 is the <em>expected</em> result
 *       of a passing authorisation check, so it must not be read as session
 *       death. If a session-check URL is configured it is probed to settle the
 *       question; otherwise a rate-limited speculative re-auth is allowed so a
 *       burst of denials cannot cause a re-auth storm.</li>
 * </ol>
 *
 * <p>Refreshes are serialised per identity: concurrent workers that need the same
 * identity's session wait for one login rather than stampeding the login
 * endpoint.
 */
public final class SessionManager {

    /** Minimum gap between speculative re-auths when liveness cannot be proven. */
    private static final long SPECULATIVE_REAUTH_INTERVAL_MILLIS = 10_000L;
    /** How long a successful liveness probe is trusted. */
    private static final long LIVENESS_CACHE_MILLIS = 5_000L;
    /** Backoff after a failed login, so a broken script does not hammer the app. */
    private static final long FAILURE_BACKOFF_MILLIS = 3_000L;

    private final MontoyaApi api;
    private final Configuration configuration;
    private final AuthScriptEngine scriptEngine;
    private final RequestMutator mutator;
    private final ScriptHttp scriptHttp;

    private final Map<String, SessionState> states = new ConcurrentHashMap<>();
    private final ScheduledExecutorService keepAlive;
    /** Notified with (identityId, login traffic) after each authentication. */
    private volatile java.util.function.BiConsumer<String, List<HttpRequestResponse>> transcriptListener;

    public SessionManager(MontoyaApi api, Configuration configuration, AuthScriptEngine scriptEngine) {
        this.api = api;
        this.configuration = configuration;
        this.scriptEngine = scriptEngine;
        this.mutator = new RequestMutator(configuration);
        this.scriptHttp = new ScriptHttp(api, configuration.settings());
        this.keepAlive = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "auth-check-keepalive");
            thread.setDaemon(true);
            return thread;
        });
        this.keepAlive.scheduleWithFixedDelay(this::refreshExpiring, 10, 10, TimeUnit.SECONDS);
    }

    private SessionState state(Identity identity) {
        return states.computeIfAbsent(identity.id(), key -> new SessionState());
    }

    // -- material ------------------------------------------------------------

    /**
     * Current auth material for an identity, authenticating first if there is no
     * live session or the configured lifetime has elapsed.
     *
     * @return the material, or null when authentication failed
     */
    public AuthMaterial materialFor(Identity identity) {
        SessionState state = state(identity);
        if (isUsable(identity, state)) {
            return state.material;
        }
        state.lock.lock();
        try {
            // Another worker may have logged in while this one waited.
            if (isUsable(identity, state)) {
                return state.material;
            }
            if (state.material == null && state.lastError != null
                    && System.currentTimeMillis() - state.lastAttemptMillis < FAILURE_BACKOFF_MILLIS) {
                return null;
            }
            AuthOutcome outcome = login(identity, state);
            return outcome.success() ? state.material : null;
        } finally {
            state.lock.unlock();
        }
    }

    private boolean isUsable(Identity identity, SessionState state) {
        AuthMaterial material = state.material;
        if (material == null) {
            return false;
        }
        long lifetime = identity.refreshIntervalSeconds();
        return lifetime <= 0 || material.ageMillis() < lifetime * 1_000L;
    }

    /** Forces a fresh login. Used by the UI's "Test authentication now" button. */
    public AuthOutcome authenticateNow(Identity identity) {
        SessionState state = state(identity);
        state.lock.lock();
        try {
            return login(identity, state);
        } finally {
            state.lock.unlock();
        }
    }

    /** Registers a sink for login traffic, e.g. the project-file repository. */
    public void onAuthTranscript(java.util.function.BiConsumer<String, List<HttpRequestResponse>> listener) {
        this.transcriptListener = listener;
    }

    private AuthOutcome login(Identity identity, SessionState state) {
        state.lastAttemptMillis = System.currentTimeMillis();
        AuthOutcome outcome = scriptEngine.authenticate(identity, state.vars);
        state.lastLog = outcome.log();
        state.lastTranscript = outcome.transcript();
        var listener = transcriptListener;
        if (listener != null && !outcome.transcript().isEmpty()) {
            listener.accept(identity.id(), outcome.transcript());
        }
        if (outcome.success()) {
            state.material = outcome.material();
            state.lastError = null;
            state.livenessCheckedAtMillis = 0L;
            state.reAuthCount++;
        } else {
            state.material = null;
            state.lastError = outcome.error();
            api.logging().logToError("[auth-check] Authentication failed for '" + identity.name() + "': "
                    + outcome.error());
        }
        return outcome;
    }

    public void invalidate(Identity identity) {
        SessionState state = state(identity);
        state.material = null;
        state.livenessCheckedAtMillis = 0L;
    }

    /** Drops all cached sessions and script state for an identity. */
    public void forget(String identityId) {
        states.remove(identityId);
    }

    // -- session death detection --------------------------------------------

    /**
     * True when a replayed response proves this identity's session has expired.
     * Only the identity's own invalid-session regex counts as proof here.
     */
    public boolean isDefinitelyExpired(Identity identity, HttpResponse response) {
        if (response == null || Text.isBlank(identity.sessionInvalidRegex())) {
            return false;
        }
        return Patterns.find(identity.sessionInvalidRegex(), responseText(response));
    }

    /**
     * Decides whether a denied response should trigger re-authentication.
     *
     * <p>A denial is the expected outcome of a correctly enforced authorisation
     * check, so this deliberately errs towards <em>not</em> re-authenticating.
     */
    public boolean shouldReauthAfterDenial(Identity identity) {
        if (!identity.reauthOnDenied()) {
            return false;
        }
        SessionState state = state(identity);

        if (!Text.isBlank(identity.sessionCheckUrl())) {
            return !isSessionAlive(identity, state);
        }

        // No liveness probe available: allow an occasional speculative re-auth.
        long now = System.currentTimeMillis();
        synchronized (state.speculativeLock) {
            if (now - state.lastSpeculativeReauthMillis < SPECULATIVE_REAUTH_INTERVAL_MILLIS) {
                return false;
            }
            state.lastSpeculativeReauthMillis = now;
        }
        return true;
    }

    /**
     * Probes the identity's session-check URL, caching the answer briefly so a
     * burst of denials costs one extra request rather than one per denial.
     */
    public boolean isSessionAlive(Identity identity, SessionState state) {
        long now = System.currentTimeMillis();
        if (now - state.livenessCheckedAtMillis < LIVENESS_CACHE_MILLIS) {
            return state.aliveAtLastCheck;
        }
        boolean alive = probeSession(identity, state.material);
        state.livenessCheckedAtMillis = System.currentTimeMillis();
        state.aliveAtLastCheck = alive;
        return alive;
    }

    public boolean isSessionAlive(Identity identity) {
        return isSessionAlive(identity, state(identity));
    }

    private boolean probeSession(Identity identity, AuthMaterial material) {
        String url = identity.sessionCheckUrl();
        if (Text.isBlank(url) || material == null) {
            return true;
        }
        try {
            HttpRequest probe = mutator.applyIdentity(
                    HttpRequest.httpRequestFromUrl(url.trim()), identity, material);
            HttpRequestResponse result = scriptHttp.send(probe, false);
            if (result == null || !result.hasResponse()) {
                // Cannot tell -- assume alive so a flaky probe does not cause a
                // pointless login on every denial.
                return true;
            }
            HttpResponse response = result.response();
            if (!Text.isBlank(identity.sessionValidRegex())) {
                return Patterns.find(identity.sessionValidRegex(), responseText(response));
            }
            short status = response.statusCode();
            return status >= 200 && status < 400;
        } catch (Exception e) {
            api.logging().logToError("[auth-check] Session check failed for '" + identity.name() + "': " + e);
            return true;
        }
    }

    private String responseText(HttpResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append(response.statusCode()).append(' ').append(Text.nullToEmpty(response.reasonPhrase())).append('\n');
        response.headers().forEach(header -> sb.append(header.name()).append(": ").append(header.value()).append('\n'));
        sb.append('\n').append(response.bodyToString());
        return sb.toString();
    }

    // -- keep-alive ----------------------------------------------------------

    /** Re-logs-in identities whose configured session lifetime is nearly up. */
    private void refreshExpiring() {
        try {
            for (Identity identity : configuration.enabledIdentities()) {
                long lifetime = identity.refreshIntervalSeconds();
                if (lifetime <= 0 || !identity.hasScript()) {
                    continue;
                }
                SessionState state = states.get(identity.id());
                if (state == null || state.material == null) {
                    continue;
                }
                // Refresh at 80% of the stated lifetime so in-flight replays are
                // not the ones that discover the session has gone.
                long refreshAfterMillis = Math.max(1_000L, (long) (lifetime * 1_000L * 0.8));
                if (state.material.ageMillis() >= refreshAfterMillis && state.lock.tryLock()) {
                    try {
                        if (state.material != null && state.material.ageMillis() >= refreshAfterMillis) {
                            login(identity, state);
                        }
                    } finally {
                        state.lock.unlock();
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[auth-check] Keep-alive tick failed: " + e);
        }
    }

    public void shutdown() {
        keepAlive.shutdownNow();
    }

    // -- status reporting for the UI ----------------------------------------

    public String statusFor(Identity identity) {
        SessionState state = states.get(identity.id());
        if (state == null || (state.material == null && state.lastError == null)) {
            return "No session yet";
        }
        if (state.material == null) {
            return "Failed: " + Text.abbreviate(state.lastError, 200);
        }
        long ageSeconds = state.material.ageMillis() / 1000L;
        return "Authenticated " + ageSeconds + "s ago (" + state.reAuthCount + " login"
                + (state.reAuthCount == 1 ? "" : "s") + " this session)";
    }

    public String lastLogFor(Identity identity) {
        SessionState state = states.get(identity.id());
        return state == null ? "" : Text.nullToEmpty(state.lastLog);
    }

    /** The requests and responses of this identity's most recent login. */
    public List<HttpRequestResponse> lastTranscriptFor(Identity identity) {
        SessionState state = states.get(identity.id());
        return state == null ? List.of() : state.lastTranscript;
    }

    /** Seeds the in-memory transcript from one restored from the project. */
    public void restoreTranscript(String identityId, List<HttpRequestResponse> exchanges) {
        if (exchanges != null && !exchanges.isEmpty()) {
            states.computeIfAbsent(identityId, key -> new SessionState()).lastTranscript = List.copyOf(exchanges);
        }
    }

    /** Per-identity session state. Package-visible so the manager can probe it. */
    public static final class SessionState {
        private final ReentrantLock lock = new ReentrantLock();
        private final Object speculativeLock = new Object();
        /** Persistent script scratch space, e.g. refresh tokens. */
        private final Map<String, String> vars = new ConcurrentHashMap<>();

        private volatile AuthMaterial material;
        private volatile String lastError;
        private volatile String lastLog = "";
        private volatile List<HttpRequestResponse> lastTranscript = List.of();
        private volatile long lastAttemptMillis;
        private volatile long lastSpeculativeReauthMillis;
        private volatile long livenessCheckedAtMillis;
        private volatile boolean aliveAtLastCheck = true;
        private volatile int reAuthCount;
    }
}
