package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.auth.AuthScriptEngine;
import com.omnicybersecurity.authcheck.auth.ScriptParam;
import com.omnicybersecurity.authcheck.auth.ScriptParamExtractor;
import com.omnicybersecurity.authcheck.auth.ScriptParams;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.util.Text;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    @Test
    void everyTemplateDeclaresTheCredentialsItReads() {
        // An example that documents its variables only in a comment is the exact
        // problem the params block exists to remove, so no example may do it.
        ScriptTemplates.all().forEach((title, body) -> {
            ScriptParams params = ScriptParamExtractor.extract(body);
            assertTrue(params.declared(), () -> "template '" + title + "' declares no params block");
            assertFalse(params.isEmpty(), () -> "template '" + title + "' declares an empty params block");
            assertEquals(List.of(), params.problems(),
                    () -> "template '" + title + "' has a bad declaration: " + params.problems());
        });
    }

    @Test
    void everyDeclaredCredentialIsActuallyRead() {
        // A declared param the script never reads is a field the tester fills in
        // for nothing, and usually means a rename went half-done.
        ScriptTemplates.all().forEach((title, body) -> {
            for (ScriptParam param : ScriptParamExtractor.extract(body).params()) {
                assertTrue(body.contains("creds." + param.name())
                                || body.contains("creds['" + param.name() + "']"),
                        () -> "template '" + title + "' declares '" + param.name()
                              + "' but never reads creds." + param.name());
            }
        });
    }

    @Test
    void everyCredentialReadIsDeclared() {
        // The complement of the test above, and the one that catches the real
        // mistake: declaring eight of the nine variables a script reads, so the
        // ninth is invisible until the login fails.
        Pattern read = Pattern.compile("creds\\.([A-Za-z_][A-Za-z0-9_]*)");
        ScriptTemplates.all().forEach((title, body) -> {
            ScriptParams params = ScriptParamExtractor.extract(body);
            Matcher matcher = read.matcher(body);
            while (matcher.find()) {
                String name = matcher.group(1);
                assertTrue(params.declares(name),
                        () -> "template '" + title + "' reads creds." + name + " without declaring it");
            }
        });
    }

    @Test
    void secretsAreDeclaredAsSecrets() {
        // The masking heuristic is a guess; a declaration is not. Any example
        // that gets this wrong teaches the wrong habit.
        ScriptTemplates.all().forEach((title, body) -> {
            for (ScriptParam param : ScriptParamExtractor.extract(body).params()) {
                if (Text.looksSecret(param.name())) {
                    assertEquals(ScriptParam.Type.SECRET, param.type(),
                            () -> "template '" + title + "' declares '" + param.name()
                                  + "' as " + param.type() + " rather than SECRET");
                }
            }
        });
    }

    @Test
    void theApiReferenceCompilesAndItsParamsBlockIsValid() throws Exception {
        // Not bundled, so nothing above covers it -- and it is the file people
        // copy declarations out of, which makes it the worst one to get wrong.
        Path reference = Path.of("scripts", "_api-reference.groovy");
        assertTrue(Files.exists(reference), () -> "missing " + reference.toAbsolutePath());
        String body = Files.readString(reference, StandardCharsets.UTF_8);

        assertNull(engine.validate(body), () -> engine.validate(body));

        ScriptParams params = ScriptParamExtractor.extract(body);
        assertTrue(params.declared(), "the reference must demonstrate a params block");
        assertEquals(List.of(), params.problems(), params.problems().toString());
        assertTrue(params.params().size() >= 7,
                () -> "the reference should show every type, got " + params.params().size());
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
