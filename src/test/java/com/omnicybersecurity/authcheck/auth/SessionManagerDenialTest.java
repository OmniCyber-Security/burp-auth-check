package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import com.omnicybersecurity.authcheck.TestApis;
import com.omnicybersecurity.authcheck.config.ConfigStore;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.support.FakeHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How a denied replay decides whether to re-authenticate. The session-check URL,
 * when set, always decides; the "re-authenticate when denied" option only
 * governs the speculative re-auth used when there is no check URL.
 */
class SessionManagerDenialTest {

    private static final String CHECK_URL = "https://app.example.com/api/me";

    private MontoyaObjectFactory previousFactory;
    private AuthScriptEngine engine;
    private SessionManager sessions;
    private final List<String> probed = new ArrayList<>();
    private volatile HttpResponse probeResponse = FakeHttp.response(200, "{\"email\":\"a@example.com\"}");

    @BeforeEach
    void setUp() {
        previousFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] { MontoyaObjectFactory.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "httpRequestFromUrl" -> FakeHttp.requestForUrl((String) args[0]);
                    case "requestOptions" -> Proxy.newProxyInstance(getClass().getClassLoader(),
                            new Class<?>[] { RequestOptions.class }, (p, m, a) -> p);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        MontoyaApi api = api();
        engine = new AuthScriptEngine(api, new Settings());
        sessions = new SessionManager(api, new Configuration(new ConfigStore(TestApis.montoyaApi())), engine);
    }

    @AfterEach
    void tearDown() {
        sessions.shutdown();
        engine.shutdown();
        ObjectFactoryLocator.FACTORY = previousFactory;
    }

    @Test
    void withTheOptionOffACheckUrlReportingADeadSessionStillTriggersReauth() {
        Identity identity = loggedIn(false, CHECK_URL);
        probeResponse = FakeHttp.response(401, "");

        assertTrue(sessions.shouldReauthAfterDenial(identity));
        assertEquals(List.of(CHECK_URL), probed);
    }

    @Test
    void withTheOptionOffACheckUrlReportingALiveSessionDoesNotReauth() {
        Identity identity = loggedIn(false, CHECK_URL);

        assertFalse(sessions.shouldReauthAfterDenial(identity));
        assertEquals(List.of(CHECK_URL), probed);
    }

    @Test
    void withTheOptionOffAndNoCheckUrlADenialIsEnforcement() {
        Identity identity = loggedIn(false, "");

        assertFalse(sessions.shouldReauthAfterDenial(identity));
        assertTrue(probed.isEmpty());
    }

    @Test
    void withTheOptionOnACheckUrlStillDecides() {
        Identity identity = loggedIn(true, CHECK_URL);

        assertFalse(sessions.shouldReauthAfterDenial(identity));
        assertEquals(List.of(CHECK_URL), probed);
    }

    @Test
    void withTheOptionOnAndNoCheckUrlASpeculativeReauthIsRateLimited() {
        Identity identity = loggedIn(true, "");

        assertTrue(sessions.shouldReauthAfterDenial(identity));
        assertFalse(sessions.shouldReauthAfterDenial(identity));
        assertTrue(probed.isEmpty());
    }

    // -- plumbing ------------------------------------------------------------

    private Identity loggedIn(boolean reauthOnDenied, String checkUrl) {
        Identity identity = new Identity("id", "User");
        identity.authScript("return [headers: ['Authorization': 'Bearer t']]");
        identity.reauthOnDenied(reauthOnDenied);
        identity.sessionCheckUrl(checkUrl);
        assertNotNull(sessions.materialFor(identity), () -> sessions.statusFor(identity));
        return identity;
    }

    private MontoyaApi api() {
        Logging logging = (Logging) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { Logging.class },
                (proxy, method, args) -> method.getReturnType() == PrintStream.class
                        ? new PrintStream(OutputStream.nullOutputStream()) : null);
        Http http = (Http) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { Http.class },
                (proxy, method, args) -> {
                    if (!"sendRequest".equals(method.getName())) {
                        throw new UnsupportedOperationException(method.getName());
                    }
                    HttpRequest request = (HttpRequest) args[0];
                    synchronized (probed) {
                        probed.add(request.url());
                    }
                    return FakeHttp.exchange(request, probeResponse);
                });
        return (MontoyaApi) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "http" -> http;
                    case "logging" -> logging;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
