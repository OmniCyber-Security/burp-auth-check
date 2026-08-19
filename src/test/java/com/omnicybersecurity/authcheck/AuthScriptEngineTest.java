package com.omnicybersecurity.authcheck;

import com.omnicybersecurity.authcheck.auth.AuthOutcome;
import com.omnicybersecurity.authcheck.auth.AuthScriptEngine;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.Identity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exercises the Groovy engine end to end, minus anything that needs the network. */
class AuthScriptEngineTest {

    private Settings settings;
    private AuthScriptEngine engine;
    private Identity identity;
    private Map<String, String> vars;

    @BeforeEach
    void setUp() {
        settings = new Settings();
        engine = new AuthScriptEngine(TestApis.montoyaApi(), settings);
        identity = new Identity("id-1", "User 1");
        identity.credentials().put("username", "alice");
        identity.credentials().put("token", "abc123");
        vars = new HashMap<>();
    }

    @AfterEach
    void tearDown() {
        engine.shutdown();
    }

    @Test
    void readsCredentialsAndReturnsHeaders() {
        identity.authScript("return [headers: ['Authorization': \"Bearer ${creds.token}\"]]");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success(), () -> "expected success but got: " + outcome.error());
        assertEquals("Bearer abc123", outcome.material().headers().get("Authorization"));
    }

    @Test
    void bareStringGoesIntoTheIdentitysTokenHeader() {
        identity.tokenHeaderName("X-Auth");
        identity.authScript("return 'Bearer zzz'");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success());
        assertEquals("Bearer zzz", outcome.material().headers().get("X-Auth"));
    }

    @Test
    void bareMapIsTreatedAsHeaders() {
        identity.authScript("return ['X-Api-Key': creds.token]");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success());
        assertEquals("abc123", outcome.material().headers().get("X-Api-Key"));
    }

    @Test
    void cookiesAndParamsAreCarried() {
        identity.authScript("""
                return [
                    cookies: ['JSESSIONID': 'sess-1'],
                    params : [[type: 'BODY', name: 'csrf', value: 'tok']]
                ]
                """);

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success());
        assertEquals("sess-1", outcome.material().cookies().get("JSESSIONID"));
        assertEquals(1, outcome.material().params().size());
        assertEquals("csrf", outcome.material().params().get(0).name());
    }

    @Test
    void varsPersistBetweenRuns() {
        identity.authScript("""
                if (!vars.counter) { vars.counter = '1' } else { vars.counter = String.valueOf(vars.counter as int) }
                vars.seen = 'yes'
                return [headers: ['X-Run': vars.counter]]
                """);

        assertTrue(engine.authenticate(identity, vars).success());
        assertEquals("yes", vars.get("seen"), "vars must survive so refresh-token flows work");
    }

    @Test
    void jsonSlurperIsAvailableToScripts() {
        identity.authScript("""
                def parsed = new groovy.json.JsonSlurper().parseText('{"access_token":"t-9"}')
                return [headers: ['Authorization': "Bearer ${parsed.access_token}"]]
                """);

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success(), () -> "expected success but got: " + outcome.error());
        assertEquals("Bearer t-9", outcome.material().headers().get("Authorization"));
    }

    @Test
    void thrownExceptionBecomesAReportedFailure() {
        identity.authScript("throw new IllegalStateException('login rejected: HTTP 500')");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertFalse(outcome.success());
        assertNotNull(outcome.error());
        assertTrue(outcome.error().contains("login rejected"), () -> "error was: " + outcome.error());
    }

    @Test
    void scriptProducingNothingUsableIsAFailureNotASilentPass() {
        // Sending unauthenticated requests here would manufacture false bypasses.
        identity.authScript("log.info 'did nothing'");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertFalse(outcome.success());
        assertTrue(outcome.error().contains("no headers"), () -> "error was: " + outcome.error());
    }

    @Test
    void staticHeadersAloneMeanTheScriptNeedNotReturnMaterial() {
        identity.staticHeaders("X-Fixed: yes");
        identity.authScript("log.info 'session established out of band'");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success());
    }

    @Test
    void identityWithoutAScriptSucceedsWithEmptyMaterial() {
        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.success());
        assertTrue(outcome.material().isEmpty());
    }

    @Test
    void runawayScriptIsTimedOutRatherThanWedgingAWorker() {
        settings.scriptTimeoutSeconds(1);
        identity.authScript("while (true) { Thread.sleep(50) }");

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertFalse(outcome.success());
        assertTrue(outcome.error().contains("timed out"), () -> "error was: " + outcome.error());
    }

    @Test
    void syntaxErrorsAreReportedByTheValidator() {
        assertNull(engine.validate("return [headers: [:]]"));
        assertNotNull(engine.validate("return [headers: "));
    }

    @Test
    void logOutputIsCapturedForTheUi() {
        identity.authScript("""
                log.info 'starting'
                log.warn 'careful'
                return 'Bearer x'
                """);

        AuthOutcome outcome = engine.authenticate(identity, vars);

        assertTrue(outcome.log().contains("starting"));
        assertTrue(outcome.log().contains("careful"));
    }
}
