package com.omnicybersecurity.authcheck.auth;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The declaration is read from the syntax tree, so these tests are as much
 * about what Groovy's parser hands back as about our own logic.
 */
class ScriptParamExtractorTest {

    @Test
    void aScriptWithNoParamsBlockDeclaresNothing() {
        ScriptParams params = ScriptParamExtractor.extract("return [headers: ['A': 'b']]");

        assertFalse(params.declared(), "an undeclared script must keep the free-form table");
        assertTrue(params.isEmpty());
    }

    @Test
    void readsNamesTypesAndOptionality() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'base',     type: URL,    required: true, label: 'Base URL'
                    param 'username', type: STRING, required: true
                    param 'password', type: SECRET, required: true
                    param 'totpSecret', type: SECRET, help: 'Base32 secret from the QR code'
                }
                return 'x'
                """);

        assertTrue(params.declared());
        assertEquals(List.of("base", "username", "password", "totpSecret"),
                params.params().stream().map(ScriptParam::name).toList());
        assertEquals(List.of(), params.problems());

        ScriptParam base = params.find("base");
        assertEquals(ScriptParam.Type.URL, base.type());
        assertTrue(base.required());
        assertEquals("Base URL", base.label());

        ScriptParam totp = params.find("totpSecret");
        assertFalse(totp.required(), "a param is optional unless it says otherwise");
        assertTrue(totp.secret());
        assertEquals("Base32 secret from the QR code", totp.help());
    }

    @Test
    void defaultIsUsableAsAnOptionName() {
        // 'default' is a Groovy keyword; this pins down that it survives as a
        // named argument, because it is the natural word for the option.
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'scope', default: 'openid profile offline_access'
                }
                return 'x'
                """);

        assertEquals(List.of(), params.problems());
        assertEquals("openid profile offline_access", params.find("scope").defaultValue());
    }

    @Test
    void defaultValueIsAcceptedToo() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'scope', defaultValue: 'openid' }
                return 'x'
                """);

        assertEquals("openid", params.find("scope").defaultValue());
    }

    @Test
    void choicesImplyAChoiceParam() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'env', choices: ['staging', 'production'] }
                return 'x'
                """);

        assertEquals(ScriptParam.Type.CHOICE, params.find("env").type());
        assertEquals(List.of("staging", "production"), params.find("env").choices());
    }

    @Test
    void nothingInTheScriptRuns() {
        // If extraction executed the source, this would throw rather than parse.
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'token', type: SECRET, required: true }
                throw new IllegalStateException('the script itself must not run')
                """);

        assertTrue(params.declared());
        assertEquals(List.of("token"), params.params().stream().map(ScriptParam::name).toList());
    }

    @Test
    void helpTextMayBeSplitAcrossLines() {
        // Help worth writing runs longer than a line of code should, so authors
        // will join it with +; dropping the tail silently would be the worst
        // possible handling.
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'tenantId', help: 'Tenant GUID or domain. ' +
                            'Required for a single-tenant app'
                }
                return 'x'
                """);

        assertEquals("Tenant GUID or domain. Required for a single-tenant app",
                params.find("tenantId").help());
    }

    // -- mistakes in the declaration -----------------------------------------

    @Test
    void anUnknownTypeIsReported() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'token', type: PASSPHRASE }
                return 'x'
                """);

        assertEquals(1, params.problems().size(), params.problems().toString());
        assertTrue(params.problems().get(0).contains("unknown type"), params.problems().toString());
    }

    @Test
    void requiredWithADefaultIsAContradiction() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'scope', required: true, default: 'openid' }
                return 'x'
                """);

        assertEquals(1, params.problems().size(), params.problems().toString());
        assertTrue(params.problems().get(0).contains("required and also has a default"),
                params.problems().toString());
    }

    @Test
    void aMistypedOptionIsReportedRatherThanIgnored() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'username', require: true }
                return 'x'
                """);

        assertTrue(params.problems().get(0).contains("unknown option 'require'"),
                params.problems().toString());
    }

    @Test
    void aNameThatIsNotALiteralIsRejected() {
        ScriptParams params = ScriptParamExtractor.extract("""
                def which = 'user' + 'name'
                params { param which, required: true }
                return 'x'
                """);

        assertTrue(params.isEmpty());
        assertTrue(params.problems().get(0).contains("literal name"), params.problems().toString());
    }

    @Test
    void aDuplicateNameIsReported() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'username', required: true
                    param 'username', type: SECRET
                }
                return 'x'
                """);

        assertEquals(1, params.params().size());
        assertTrue(params.problems().get(0).contains("more than once"), params.problems().toString());
    }

    @Test
    void aDefaultThatDoesNotFitItsTypeIsReported() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params { param 'timeout', type: INT, default: 'soon' }
                return 'x'
                """);

        assertTrue(params.problems().get(0).contains("whole number"), params.problems().toString());
    }

    @Test
    void aScriptThatDoesNotParseDeclaresNothing() {
        assertFalse(ScriptParamExtractor.extract("params { param 'a' ").declared());
    }

    // -- the checks the engine and the form share ----------------------------

    @Test
    void defaultsFillInForBlankFieldsOnly() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'scope', default: 'openid'
                    param 'tenant', default: 'organizations'
                }
                return 'x'
                """);
        Map<String, String> creds = new LinkedHashMap<>();
        creds.put("scope", "");
        creds.put("tenant", "contoso.example");

        Map<String, String> effective = params.withDefaults(creds);

        assertEquals("openid", effective.get("scope"));
        assertEquals("contoso.example", effective.get("tenant"), "a typed value must win over the default");
        assertEquals(List.of("scope"), params.defaulted(creds));
    }

    @Test
    void onlyRequiredFieldsAreReportedMissing() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'username', required: true
                    param 'password', type: SECRET, required: true
                    param 'totpSecret', type: SECRET
                }
                return 'x'
                """);
        Map<String, String> creds = new LinkedHashMap<>();
        creds.put("username", "alice");

        assertEquals(List.of("password"), params.missingRequired(creds));
    }

    @Test
    void typedValuesAreChecked() {
        ScriptParams params = ScriptParamExtractor.extract("""
                params {
                    param 'base', type: URL
                    param 'retries', type: INT
                    param 'env', choices: ['staging', 'production']
                }
                return 'x'
                """);
        Map<String, String> creds = new LinkedHashMap<>();
        creds.put("base", "target.example.com");
        creds.put("retries", "lots");
        creds.put("env", "dev");

        List<String> problems = params.valueProblems(creds);

        assertEquals(3, problems.size(), problems.toString());
        assertTrue(problems.get(0).contains("absolute URL"), problems.toString());
        assertTrue(problems.get(1).contains("whole number"), problems.toString());
        assertTrue(problems.get(2).contains("staging, production"), problems.toString());
    }

    @Test
    void aBlankOptionalValueIsNotAProblem() {
        ScriptParam param = ScriptParam.of("retries", ScriptParam.Type.INT);

        assertNull(param.problemWith(""));
        assertNull(param.problemWith(null));
        assertNotNull(param.problemWith("soon"));
    }
}
