package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.http.RedirectionMode;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import com.omnicybersecurity.authcheck.support.FakePersistence;
import com.omnicybersecurity.authcheck.support.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two ways a cookie-authenticated session can silently fail to reach the
 * wire, both of which look identical to the tester: "the replay has no cookies".
 */
class ScriptCookieHandlingTest {

    private FakePersistence factory;
    private RecordedRequest recorder;
    private Settings settings;

    @BeforeEach
    void setUp() {
        // Only the Montoya object factory is needed here, for RequestOptions.
        factory = FakePersistence.installFactoryOnly();
        recorder = new RecordedRequest();
        recorder.reset();
        settings = new Settings();
    }

    @AfterEach
    void tearDown() {
        factory.close();
    }

    // -- returning cookies the wrong way ------------------------------------

    @Test
    void aBareMapIsAppliedAsHeadersAndSaysSo() {
        // `return http.cookies(resp)` produces exactly this shape. It is accepted
        // as the header shorthand, but silently turning a session cookie into a
        // header is the kind of thing that costs an afternoon, so it must warn.
        AuthOutcome outcome = run("return ['JSESSIONID': 'abc123']");

        assertEquals(Map.of("JSESSIONID", "abc123"), outcome.material().headers());
        assertTrue(outcome.material().cookies().isEmpty());
        assertTrue(outcome.log().contains("REQUEST HEADERS"),
                () -> "expected a warning, log was:\n" + outcome.log());
        assertTrue(outcome.log().contains("[cookies: ..."),
                () -> "the warning must name the fix, log was:\n" + outcome.log());
    }

    @Test
    void wrappingInCookiesProducesCookies() {
        AuthOutcome outcome = run("return [cookies: ['JSESSIONID': 'abc123']]");

        assertEquals(Map.of("JSESSIONID", "abc123"), outcome.material().cookies());
        assertTrue(outcome.material().headers().isEmpty());
        assertTrue(outcome.log().isBlank() || !outcome.log().contains("REQUEST HEADERS"),
                "the correct form must not warn");
    }

    @Test
    void aCookieHeaderStringIsSplitIntoCookies() {
        AuthOutcome outcome = run("return [cookies: 'JSESSIONID=abc123; csrf=xyz']");

        assertEquals(Map.of("JSESSIONID", "abc123", "csrf", "xyz"), outcome.material().cookies());
    }

    @Test
    void theHeaderShorthandStillWorksForActualHeaders() {
        AuthOutcome outcome = run("return ['X-Api-Key': 'k-1']");

        assertEquals(Map.of("X-Api-Key", "k-1"), outcome.material().headers());
    }

    // -- a lookup that missed -----------------------------------------------

    @Test
    void anAllBlankSessionIsAFailureNotASuccess() {
        // http.cookies(resp)['wrong-name'] returns null. Sending ".x=" would look
        // authenticated and make every verdict downstream meaningless.
        AuthOutcome outcome = run("def t = null; return [cookies: ['.elevate-session-id': t]]");

        assertFalse(outcome.success(), "a blank session must not report success");
        assertTrue(outcome.error().contains(".elevate-session-id"),
                () -> "the error must name the offender, was: " + outcome.error());
    }

    @Test
    void aPartiallyBlankMaterialIsKeptButWarned() {
        AuthOutcome outcome = run(
                "return [cookies: ['sid': 'real-value', 'csrf': '']]");

        assertTrue(outcome.success(), "there is still a usable value");
        assertTrue(outcome.log().contains("cookie csrf"),
                () -> "expected a warning naming the blank entry, log was:\n" + outcome.log());
    }

    // -- losing Set-Cookie to a redirect ------------------------------------

    @Test
    void scriptRequestsDoNotFollowRedirectsEvenWhenReplaysDo() {
        // A login's Set-Cookie usually arrives on the 302. Following it would
        // discard the session, so the replay setting must not reach scripts.
        settings.followRedirectsOnReplay(true);

        run("http.get('https://target.example.com/login'); return 'Bearer x'");

        assertEquals(java.util.List.of(RedirectionMode.NEVER), recorder.redirectionModes(),
                "script requests must never follow redirects implicitly");
    }

    @Test
    void aScriptCanStillOptIntoFollowingRedirects() {
        run("http.send(http.request('https://target.example.com/login'), true); return 'Bearer x'");

        assertEquals(java.util.List.of(RedirectionMode.ALWAYS), recorder.redirectionModes());
    }

    private AuthOutcome run(String script) {
        Identity identity = new Identity("id", "User");
        identity.authScript(script);
        AuthScriptEngine engine = new AuthScriptEngine(
                recorder.api(FakeHttp.exchange(
                        FakeHttp.request(Map.of("Host", "target.example.com")),
                        FakeHttp.response(302, "", Map.of("Location", "/home")))),
                settings);
        try {
            return engine.authenticate(identity, new HashMap<>());
        } finally {
            engine.shutdown();
        }
    }
}
