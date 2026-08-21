package com.omnicybersecurity.authcheck.ui;

import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.auth.ScriptParamExtractor;
import com.omnicybersecurity.authcheck.auth.ScriptParams;
import com.omnicybersecurity.authcheck.model.Identity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The credentials editor, exercised without showing a window.
 *
 * <p>What is worth testing here is not the layout but the promise the layout
 * rests on: editing a script re-draws the form and never destroys a value.
 */
class CredentialsFormTest {

    private CredentialsForm form;
    private Identity identity;

    @BeforeEach
    void setUp() {
        form = new CredentialsForm(TestApis.montoyaApi(), () -> { });
        identity = new Identity("id-1", "User 1");
        identity.credentials().clear();
    }

    private static ScriptParams params(String source) {
        return ScriptParamExtractor.extract(source);
    }

    @Test
    void declaredValuesRoundTripThroughTheForm() {
        identity.credentials().put("username", "alice");
        identity.credentials().put("password", "hunter2");
        form.setParams(params("""
                params {
                    param 'username', required: true
                    param 'password', type: SECRET, required: true
                }
                return 'x'
                """));
        form.load(identity);

        form.applyTo(identity);

        assertEquals("alice", identity.credentials().get("username"));
        assertEquals("hunter2", identity.credentials().get("password"));
    }

    @Test
    void aCredentialTheScriptDoesNotDeclareIsKept() {
        identity.credentials().put("username", "alice");
        identity.credentials().put("legacyApiKey", "kept");
        form.setParams(params("params { param 'username', required: true }\nreturn 'x'"));
        form.load(identity);

        form.applyTo(identity);

        assertEquals("kept", identity.credentials().get("legacyApiKey"),
                "an undeclared credential must survive in the table underneath");
    }

    @Test
    void switchingScriptsDoesNotDestroyAValueTheNewScriptStoppedDeclaring() {
        // The keystroke-by-keystroke case: the tester edits the script and the
        // form is re-derived underneath them. A password entered against the old
        // script has to end up somewhere it can still be seen and re-used.
        identity.credentials().put("username", "alice");
        identity.credentials().put("roleId", "admin");
        form.setParams(params("""
                params {
                    param 'username', required: true
                    param 'roleId', required: true
                }
                return 'x'
                """));
        form.load(identity);

        form.setParams(params("params { param 'username', required: true }\nreturn 'x'"));
        form.applyTo(identity);

        assertEquals("alice", identity.credentials().get("username"));
        assertEquals("admin", identity.credentials().get("roleId"),
                "the value moved out of the form and must not have been dropped");
    }

    @Test
    void declaredFieldsComeFirstInDeclarationOrder() {
        identity.credentials().put("extra", "z");
        identity.credentials().put("password", "hunter2");
        identity.credentials().put("username", "alice");
        form.setParams(params("""
                params {
                    param 'username', required: true
                    param 'password', type: SECRET, required: true
                }
                return 'x'
                """));
        form.load(identity);

        form.applyTo(identity);

        assertEquals(List.of("username", "password", "extra"),
                List.copyOf(identity.credentials().keySet()));
    }

    @Test
    void aBlankDeclaredFieldIsNotStored() {
        // Storing "" would leave a stray empty row behind the moment the script
        // stopped declaring it.
        form.setParams(params("params { param 'totpSecret', type: SECRET }\nreturn 'x'"));
        form.load(identity);

        form.applyTo(identity);

        assertTrue(identity.credentials().isEmpty(), identity.credentials().toString());
    }

    @Test
    void anUndeclaredScriptKeepsEveryCredentialInTheTable() {
        identity.credentials().put("username", "alice");
        identity.credentials().put("token", "abc123");
        form.setParams(ScriptParams.none());
        form.load(identity);

        form.applyTo(identity);

        assertEquals(2, identity.credentials().size(), identity.credentials().toString());
        assertEquals("abc123", identity.credentials().get("token"));
    }

    @Test
    void aBooleanFieldRoundTripsAsTrueOrFalse() {
        identity.credentials().put("useDeviceCode", "true");
        form.setParams(params("params { param 'useDeviceCode', type: BOOL }\nreturn 'x'"));
        form.load(identity);

        form.applyTo(identity);

        assertEquals("true", identity.credentials().get("useDeviceCode"));
    }

    @Test
    void aChoiceFieldKeepsTheSelectedValue() {
        identity.credentials().put("env", "production");
        form.setParams(params("params { param 'env', choices: ['staging', 'production'] }\nreturn 'x'"));
        form.load(identity);

        form.applyTo(identity);

        assertEquals("production", identity.credentials().get("env"));
    }
}
