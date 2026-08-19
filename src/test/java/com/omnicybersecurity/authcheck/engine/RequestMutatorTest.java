package com.omnicybersecurity.authcheck.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import com.omnicybersecurity.authcheck.config.ConfigStore;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.Identity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** How a captured request is rewritten to belong to somebody else. */
class RequestMutatorTest {

    private Configuration configuration;
    private RequestMutator mutator;
    private Identity identity;

    /** A request as captured from the baseline user. */
    private static HttpRequest captured() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", "target.example.com");
        headers.put("Authorization", "Bearer alice-token");
        headers.put("Cookie", "consent=yes; JSESSIONID=alice-session; locale=en-GB");
        headers.put("Accept", "application/json");
        return FakeHttp.request(headers);
    }

    @BeforeEach
    void setUp() {
        configuration = new Configuration(new ConfigStore(TestApis.montoyaApi()));
        mutator = new RequestMutator(configuration);
        identity = new Identity("id-2", "User 2");
    }

    @Test
    void originalCredentialsAreReplacedByTheIdentitys() {
        AuthMaterial material = AuthMaterial.builder()
                .header("Authorization", "Bearer bob-token")
                .build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        assertEquals("Bearer bob-token", result.header("Authorization"));
        assertEquals("application/json", result.header("Accept"), "unrelated headers must survive");
    }

    @Test
    void nonSessionCookiesSurviveWhenCookieIsNotStripped() {
        // Consent and locale cookies change how the app behaves, so keeping them
        // makes the two users' requests genuinely comparable.
        identity.stripHeaders("Authorization");
        AuthMaterial material = AuthMaterial.builder().cookie("JSESSIONID", "bob-session").build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        String cookie = result.header("Cookie");
        assertTrue(cookie.contains("consent=yes"), () -> "cookie was: " + cookie);
        assertTrue(cookie.contains("locale=en-GB"), () -> "cookie was: " + cookie);
        assertTrue(cookie.contains("JSESSIONID=bob-session"), () -> "cookie was: " + cookie);
        assertFalse(cookie.contains("alice-session"), () -> "cookie was: " + cookie);
    }

    @Test
    void strippingCookieDiscardsEveryOriginalCookie() {
        identity.stripHeaders("Authorization, Cookie");
        AuthMaterial material = AuthMaterial.builder().cookie("JSESSIONID", "bob-session").build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        assertEquals("JSESSIONID=bob-session", result.header("Cookie"));
    }

    @Test
    void strippedHeaderStaysGoneWhenTheMaterialDoesNotReplaceIt() {
        identity.stripHeaders("Authorization, Cookie");
        AuthMaterial material = AuthMaterial.builder().header("X-Auth", "bob").build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        assertNull(result.header("Authorization"));
        assertNull(result.header("Cookie"));
        assertEquals("bob", result.header("X-Auth"));
    }

    @Test
    void staticHeadersOverrideTheScriptsMaterial() {
        identity.staticHeaders("Authorization: Bearer forced-by-tester");
        AuthMaterial material = AuthMaterial.builder().header("Authorization", "Bearer from-script").build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        assertEquals("Bearer forced-by-tester", result.header("Authorization"));
    }

    @Test
    void materialCanRequestExtraRemovals() {
        AuthMaterial material = AuthMaterial.builder()
                .header("Authorization", "Bearer bob")
                .removeHeader("Accept")
                .build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        assertNull(result.header("Accept"));
    }

    @Test
    void headerNamesAreMatchedCaseInsensitively() {
        identity.stripHeaders("authorization, cookie");
        AuthMaterial material = AuthMaterial.builder().header("X-Auth", "bob").build();

        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, material));

        assertNull(result.header("Authorization"));
        assertNull(result.header("Cookie"));
    }

    @Test
    void unauthenticatedReplayDropsEveryCredential() {
        FakeHttp.RequestState result = FakeHttp.stateOf(mutator.applyUnauthenticated(captured()));

        assertNull(result.header("Authorization"));
        assertNull(result.header("Cookie"));
        assertEquals("target.example.com", result.header("Host"), "the request must still be routable");
        assertEquals("application/json", result.header("Accept"));
    }

    @Test
    void emptyMaterialLeavesRequestUsableForStaticHeaderOnlyIdentities() {
        identity.stripHeaders("");
        identity.staticHeaders("X-Api-Key: fixed-key");

        FakeHttp.RequestState result =
                FakeHttp.stateOf(mutator.applyIdentity(captured(), identity, AuthMaterial.empty()));

        assertEquals("fixed-key", result.header("X-Api-Key"));
    }
}
