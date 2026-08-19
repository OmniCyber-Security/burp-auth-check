package com.omnicybersecurity.authcheck.config;

import com.omnicybersecurity.authcheck.model.Identity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The file export is the recovery path that does not depend on how Burp
 * addresses project storage, so it has to carry everything that would be
 * painful to retype -- credentials and the auth script above all.
 */
class IdentityTransferTest {

    private static Identity sample() {
        Identity identity = new Identity("id-1", "User 1 - owner");
        identity.authScript("return [cookies: ['.elevate-session-id': token]]");
        identity.credentials().put("username", "alice");
        identity.credentials().put("password", "p4ss w0rd \"quoted\"");
        identity.credentials().put("roleId", "17");
        identity.notes("owns the records under test");
        identity.staticHeaders("X-Tenant: acme");
        identity.stripHeaders("Authorization, Cookie");
        identity.tokenHeaderName("X-Auth");
        identity.refreshIntervalSeconds(240);
        identity.sessionInvalidRegex("(?i)token_expired");
        identity.sessionCheckUrl("https://target.example.com/api/me");
        identity.sessionValidRegex("\"authenticated\"\\s*:\\s*true");
        identity.reauthOnDenied(false);
        return identity;
    }

    @Test
    void everyFieldSurvivesTheRoundTrip() {
        Identity original = sample();

        Identity restored = IdentityTransfer.fromJson(IdentityTransfer.toJson(List.of(original))).get(0);

        assertEquals(original.name(), restored.name());
        assertEquals(original.authScript(), restored.authScript());
        assertEquals(original.credentialsSnapshot(), restored.credentialsSnapshot());
        assertEquals(original.notes(), restored.notes());
        assertEquals(original.staticHeaders(), restored.staticHeaders());
        assertEquals(original.stripHeaders(), restored.stripHeaders());
        assertEquals(original.tokenHeaderName(), restored.tokenHeaderName());
        assertEquals(original.refreshIntervalSeconds(), restored.refreshIntervalSeconds());
        assertEquals(original.sessionInvalidRegex(), restored.sessionInvalidRegex());
        assertEquals(original.sessionCheckUrl(), restored.sessionCheckUrl());
        assertEquals(original.sessionValidRegex(), restored.sessionValidRegex());
        assertEquals(original.reauthOnDenied(), restored.reauthOnDenied());
        assertEquals(original.enabled(), restored.enabled());
    }

    @Test
    void quotesAndRegexEscapesInCredentialsAndScriptsSurvive() {
        // Scripts and session patterns are full of quotes and backslashes; a
        // format that mangles them would corrupt the thing being recovered.
        Identity identity = new Identity("id", "Awkward");
        identity.authScript("def m = http.extractFrom(r, /name=\"csrf\"\\s+value=\"([^\"]+)\"/)");
        identity.credentials().put("password", "a\"b\\c\nd\te");

        Identity restored = IdentityTransfer.fromJson(IdentityTransfer.toJson(List.of(identity))).get(0);

        assertEquals(identity.authScript(), restored.authScript());
        assertEquals("a\"b\\c\nd\te", restored.credentials().get("password"));
    }

    @Test
    void importedIdentitiesGetFreshIdsSoTheyCannotCollide() {
        Identity original = sample();

        Identity restored = IdentityTransfer.fromJson(IdentityTransfer.toJson(List.of(original))).get(0);

        assertNotEquals(original.id(), restored.id(),
                "a re-import into the same project must not overwrite the original");
    }

    @Test
    void severalIdentitiesKeepTheirOrder() {
        List<Identity> originals = List.of(
                new Identity("a", "First"), new Identity("b", "Second"), new Identity("c", "Third"));

        List<Identity> restored = IdentityTransfer.fromJson(IdentityTransfer.toJson(originals));

        assertEquals(List.of("First", "Second", "Third"), restored.stream().map(Identity::name).toList());
    }

    @Test
    void aDisabledIdentityStaysDisabled() {
        Identity identity = sample();
        identity.enabled(false);

        assertFalse(IdentityTransfer.fromJson(IdentityTransfer.toJson(List.of(identity))).get(0).enabled());
    }

    @Test
    void theExportWarnsThatItHoldsCredentials() {
        String json = IdentityTransfer.toJson(List.of(sample()));

        assertTrue(json.contains("credentials in clear text"),
                "the file itself should say what it contains");
    }

    @Test
    void rubbishInputIsRejectedWithSomethingReadable() {
        assertThrows(RuntimeException.class, () -> IdentityTransfer.fromJson("not json at all"));
        assertThrows(IllegalArgumentException.class, () -> IdentityTransfer.fromJson("[1,2,3]"));
        assertThrows(IllegalArgumentException.class, () -> IdentityTransfer.fromJson("{\"format\":1}"));
        assertThrows(IllegalArgumentException.class,
                () -> IdentityTransfer.fromJson("{\"identities\":[]}"));
    }
}
