package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.auth.AuthScriptEngine;
import com.omnicybersecurity.authcheck.config.Settings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The example scripts ship as templates, so a broken one reaches a tester as a
 * menu entry that will not run. Compiling them here means it fails the build
 * instead.
 */
class BundledScriptsTest {

    private AuthScriptEngine engine;

    @BeforeEach
    void setUp() {
        engine = new AuthScriptEngine(TestApis.montoyaApi(), new Settings());
    }

    @AfterEach
    void tearDown() {
        engine.shutdown();
    }

    @Test
    void everyBundledScriptCompiles() {
        Map<String, String> templates = ScriptTemplates.all();
        assertFalse(templates.isEmpty(), "no templates were bundled into the jar");

        templates.forEach((title, body) -> {
            String error = engine.validate(body);
            assertNull(error, () -> "template '" + title + "' does not compile:\n" + error);
        });
    }

    @Test
    void theExamplesFromTheScriptsDirectoryAreAllThere() {
        // Named explicitly: silently dropping one from the build would otherwise
        // go unnoticed, since the menu is generated.
        Map<String, String> templates = ScriptTemplates.all();

        assertTrue(templates.size() >= 8,
                () -> "expected every example to be bundled, got " + templates.keySet());
        assertTrue(templates.containsKey("Static API key or token in a header"), templates.keySet().toString());
        assertTrue(templates.containsKey("JSON login -> bearer token"), templates.keySet().toString());
        assertTrue(templates.containsKey("HTML form login -> session cookie"), templates.keySet().toString());
        assertTrue(templates.containsKey("Login, then assume a role"), templates.keySet().toString());
        assertTrue(templates.containsKey("Login with a TOTP second factor"), templates.keySet().toString());
        assertTrue(templates.containsKey("Entra ID (Azure AD) OIDC login with TOTP"), templates.keySet().toString());
    }

    @Test
    void theReferenceStubIsNotOfferedAsATemplate() {
        // _api-reference.groovy documents the API; it is not something to insert.
        ScriptTemplates.all().keySet().forEach(title ->
                assertFalse(title.toLowerCase(java.util.Locale.ROOT).contains("api reference"),
                        () -> "the reference stub leaked into the template menu as '" + title + "'"));
    }

    @Test
    void everyTemplateHasAUsefulBody() {
        ScriptTemplates.all().forEach((title, body) -> {
            assertFalse(body.isBlank(), () -> "template '" + title + "' is empty");
            assertTrue(body.contains("return") || body.contains("throw"),
                    () -> "template '" + title + "' neither returns material nor fails");
        });
    }

    // -- title derivation ----------------------------------------------------

    @Test
    void theTitleComesFromTheFirstLineOfProse() {
        assertEquals("HTML form login -> session cookie", ScriptTemplates.titleOf("""
                /*
                 * HTML form login -> session cookie
                 *
                 * Longer explanation that should not be used.
                 */
                return 'x'
                """, "whatever.groovy"));
    }

    @Test
    void aLineCommentWorksTooAndATrailingStopIsDropped() {
        assertEquals("Does a thing", ScriptTemplates.titleOf(
                "// Does a thing.\nreturn 'x'\n", "whatever.groovy"));
    }

    @Test
    void aScriptWithNoCommentFallsBackToItsFileName() {
        assertEquals("Some example script", ScriptTemplates.titleOf(
                "return 'x'\n", "some-example-script.groovy"));
    }

    @Test
    void aWrappedOpeningSentenceIsNotUsedWhole() {
        String title = ScriptTemplates.titleOf(
                "// " + "a".repeat(200) + "\nreturn 'x'\n", "long.groovy");

        assertTrue(title.length() <= 70, () -> "title was " + title.length() + " chars");
    }
}
