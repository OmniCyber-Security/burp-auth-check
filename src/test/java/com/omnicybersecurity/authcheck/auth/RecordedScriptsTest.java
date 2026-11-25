package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.Identity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Chrome recorder (chrome-extension/) generates auth scripts from a
 * recorded login. Its golden outputs are checked here, on the side that runs
 * them: each must compile against {@code AuthScriptBase}, declare what it reads,
 * and -- the part a text comparison cannot show -- actually log in against a
 * server that hands out <em>different</em> tokens, cookies and codes from the
 * ones that were recorded. A script that replayed a recorded CSRF token would
 * pass every other check and fail here.
 */
class RecordedScriptsTest {

    private static final Path GOLDEN = Path.of("chrome-extension", "test", "golden");

    private MontoyaObjectFactory previousFactory;
    private AuthScriptEngine engine;
    private Function<FakeRequest, FakeResponse> site;
    private final List<FakeRequest> sent = new ArrayList<>();

    @BeforeEach
    void setUp() {
        previousFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] { MontoyaObjectFactory.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "httpRequestFromUrl" -> new FakeRequest("GET", (String) args[0], new LinkedHashMap<>(), "").proxy();
                    case "requestOptions" -> Proxy.newProxyInstance(getClass().getClassLoader(),
                            new Class<?>[] { RequestOptions.class }, (p, m, a) -> p);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        engine = new AuthScriptEngine(api(), new Settings());
    }

    @AfterEach
    void tearDown() {
        engine.shutdown();
        ObjectFactoryLocator.FACTORY = previousFactory;
    }

    // -- static checks over every golden -------------------------------------

    @Test
    void everyRecordedScriptCompilesAndDeclaresWhatItReads() throws Exception {
        List<Path> scripts;
        try (var files = Files.list(GOLDEN)) {
            scripts = files.filter(p -> p.toString().endsWith(".groovy")).sorted().toList();
        }
        assertTrue(scripts.size() >= 3, () -> "expected the recorder's golden scripts in " + GOLDEN.toAbsolutePath());

        Pattern read = Pattern.compile("creds\\.([A-Za-z_][A-Za-z0-9_]*)");
        for (Path script : scripts) {
            String body = Files.readString(script, StandardCharsets.UTF_8);
            assertNull(engine.validate(body), () -> script + " does not compile:\n" + engine.validate(body));

            ScriptParams params = ScriptParamExtractor.extract(body);
            assertTrue(params.declared(), () -> script + " declares no params block");
            assertEquals(List.of(), params.problems(), () -> script + ": " + params.problems());
            Matcher matcher = read.matcher(body);
            while (matcher.find()) {
                String name = matcher.group(1);
                assertTrue(params.declares(name), () -> script + " reads creds." + name + " without declaring it");
            }
        }
    }

    // -- running them against a server that changes every value --------------

    @Test
    void formLoginCarriesAFreshCsrfTokenAndReturnsTheNewSession() throws Exception {
        String csrf = random("csrf");
        String pre = random("pre");
        String session = random("sess");
        site = request -> {
            if (request.is("GET", "https://app.example.com/login")) {
                return FakeResponse.ok("<form><input type=\"hidden\" name=\"_csrf\" value=\"" + csrf + "\"></form>")
                        .cookie("pre_session", pre);
            }
            if (request.is("POST", "https://app.example.com/login")) {
                Map<String, String> form = request.form();
                boolean good = csrf.equals(form.get("_csrf"))
                        && "dave@example.com".equals(form.get("username"))
                        && "correct horse".equals(form.get("password"))
                        && request.cookie("pre_session").equals(pre);
                return good
                        ? new FakeResponse(302, "").header("Location", "/dashboard").cookie("SESSION", session)
                        : FakeResponse.ok("<form>Invalid credentials</form>");
            }
            return new FakeResponse(404, "");
        };

        AuthOutcome outcome = run("form-login", Map.of("username", "dave@example.com", "password", "correct horse"));

        assertTrue(outcome.success(), outcome::error);
        assertEquals(session, outcome.material().cookies().get("SESSION"));
        assertEquals(pre, outcome.material().cookies().get("pre_session"));
        assertEquals("https://app.example.com", sent.get(1).header("Origin"));
    }

    @Test
    void aLoginThatNoLongerMatchesFailsAtTheStepThatChanged() throws Exception {
        site = request -> request.is("GET", "https://app.example.com/login")
                ? FakeResponse.ok("<input type=\"hidden\" name=\"_csrf\" value=\"" + random("c") + "\">")
                : FakeResponse.ok("<form>Invalid credentials</form>");

        AuthOutcome outcome = run("form-login", Map.of("username", "dave@example.com", "password", "wrong"));

        assertFalse(outcome.success());
        assertTrue(outcome.error().contains("Step 2") && outcome.error().contains("HTTP 200")
                        && outcome.error().contains("recording got 302"), outcome.error());
    }

    @Test
    void aMissingTokenIsNamedRatherThanSentEmpty() throws Exception {
        site = request -> FakeResponse.ok("<html>maintenance</html>");

        AuthOutcome outcome = run("form-login", Map.of("username", "u", "password", "p"));

        assertFalse(outcome.success());
        assertTrue(outcome.error().contains("_csrf"), outcome.error());
        assertEquals(1, sent.size(), "nothing after the missing token may be sent");
    }

    @Test
    void jsonLoginReturnsTheTokenFromThisLoginNotTheRecordedOne() throws Exception {
        String token = random("eyJ");
        site = request -> {
            if (request.is("POST", "https://api.example.com/api/auth/login")) {
                boolean good = request.body.contains("\"email\":\"erin@example.com\"")
                        && request.body.contains("\"password\":\"pw-2\"")
                        && "application/json".equals(request.header("Content-Type"));
                return good
                        ? FakeResponse.ok("{\"data\":{\"accessToken\":\"" + token + "\",\"expiresIn\":300}}")
                        : new FakeResponse(401, "{\"error\":\"bad\"}");
            }
            return new FakeResponse(404, "");
        };

        AuthOutcome outcome = run("json-bearer", Map.of("username", "erin@example.com", "password", "pw-2"));

        assertTrue(outcome.success(), outcome::error);
        assertEquals("Bearer " + token, outcome.material().headers().get("Authorization"));
    }

    @Test
    void oidcFlowFollowsFreshRedirectsFormActionsAndTotp() throws Exception {
        String state = random("st");
        String code1 = random("sc1");
        String code2 = random("sc2");
        String authSession = random("as");
        String authCode = random("code");
        String portal = random("ps");
        String secret = "JBSWY3DPEHPK3PXP";
        site = request -> {
            String url = request.url;
            if (request.is("GET", "https://app.example.com/")) {
                return new FakeResponse(302, "").header("Location",
                        "https://idp.example.org/auth?client_id=portal&response_type=code&state=" + state);
            }
            if (request.method.equals("GET") && url.startsWith("https://idp.example.org/auth?")) {
                assertTrue(url.endsWith("state=" + state), url);
                return FakeResponse.ok("<form id=\"kc-form-login\" action=\"https://idp.example.org/login-actions/"
                                + "authenticate?session_code=" + code1 + "&amp;execution=e1&amp;tab_id=t\" method=\"post\">")
                        .cookie("AUTH_SESSION_ID", authSession);
            }
            if (request.method.equals("POST") && url.contains("session_code=" + code1 + "&execution=e1")) {
                Map<String, String> form = request.form();
                if (!"frank".equals(form.get("username")) || !"pw-3".equals(form.get("password"))
                        || !authSession.equals(request.cookie("AUTH_SESSION_ID"))) {
                    return FakeResponse.ok("<form id=\"kc-form-login\">Invalid</form>");
                }
                return FakeResponse.ok("<form id=\"kc-otp-login-form\" action=\"https://idp.example.org/login-actions/"
                        + "authenticate?session_code=" + code2 + "&amp;execution=otp&amp;tab_id=t\" method=\"post\">");
            }
            if (request.method.equals("POST") && url.contains("session_code=" + code2)) {
                if (!totp(secret).equals(request.form().get("otp"))) {
                    return FakeResponse.ok("<form id=\"kc-otp-login-form\">Invalid code</form>");
                }
                return new FakeResponse(302, "").header("Location",
                        "https://app.example.com/cb?state=" + state + "&code=" + authCode);
            }
            if (request.is("GET", "https://app.example.com/cb?state=" + state + "&code=" + authCode)) {
                return new FakeResponse(302, "").header("Location", "/").cookie("portal_sid", portal);
            }
            return new FakeResponse(404, "unexpected " + request.method + " " + url);
        };

        AuthOutcome outcome = run("oidc-totp",
                Map.of("username", "frank", "password", "pw-3", "totpSecret", secret));

        assertTrue(outcome.success(), () -> outcome.error() + "\n" + outcome.log());
        assertEquals(portal, outcome.material().cookies().get("portal_sid"));
        assertEquals(5, sent.size());
        assertNotEquals("Sc0de-1a2b3c", code1);
    }

    @Test
    void sameNamedCookiesOnTwoHostsStaySeparateAndAPlainTextJsonBodyCarriesTheCode() throws Exception {
        String appSession = random("app");
        String ssoSession = random("sso");
        String next = random("Cnt");
        String ref = random("Rf");
        String ticket = random("Tk");
        String appCookie = random("as");
        String secret = "JBSWY3DPEHPK3PXP";
        site = request -> {
            String url = request.url;
            if (request.is("GET", "https://app.example.com/start")) {
                return new FakeResponse(302, "").header("Location", "https://sso.example.org/login?goto=x")
                        .cookie("JSESSIONID", appSession);
            }
            if (request.is("GET", "https://sso.example.org/login?goto=x")) {
                return FakeResponse.ok("<form><input type=\"hidden\" name=\"continue\" value=\"" + next + "\">"
                        + "<p>Request ref:\u00a0" + ref + "</p></form>").cookie("JSESSIONID", ssoSession);
            }
            if (request.is("POST", "https://sso.example.org/api/authenticate")) {
                String body = request.body;
                boolean good = body.contains("\"user\":\"gina@example.com\"")
                        && body.contains("\"pass\":\"pw-4\"")
                        && body.contains("\"otp\":" + Long.parseLong(totp(secret)) + ",")
                        && body.contains("\"continue\":\"" + next + "\"")
                        && "text/plain;charset=UTF-8".equals(request.header("Content-Type"))
                        && ref.equals(request.header("X-Request-Ref"))
                        && ssoSession.equals(request.cookie("JSESSIONID"));
                return good
                        ? FakeResponse.ok("{\"goto\":\"https://app.example.com/sso/callback?ticket=" + ticket + "\"}")
                        : new FakeResponse(401, body + " " + request.headers);
            }
            if (request.is("GET", "https://app.example.com/sso/callback?ticket=" + ticket)) {
                // The app's own JSESSIONID, not the identity provider's.
                return appSession.equals(request.cookie("JSESSIONID"))
                        ? new FakeResponse(302, "").header("Location", "/home").cookie("APPSESSION", appCookie)
                        : new FakeResponse(403, "wrong session " + request.cookie("JSESSIONID"));
            }
            return new FakeResponse(404, "unexpected " + request.method + " " + url);
        };

        AuthOutcome outcome = run("sso-edge-cases",
                Map.of("username", "gina@example.com", "password", "pw-4", "totpSecret", secret));

        assertTrue(outcome.success(), () -> outcome.error() + "\n" + outcome.log());
        assertEquals(appSession, outcome.material().cookies().get("JSESSIONID"));
        assertEquals(appCookie, outcome.material().cookies().get("APPSESSION"));
    }

    // -- plumbing ------------------------------------------------------------

    private AuthOutcome run(String golden, Map<String, String> credentials) throws Exception {
        Identity identity = new Identity("id", "Recorded");
        identity.authScript(Files.readString(GOLDEN.resolve(golden + ".groovy"), StandardCharsets.UTF_8));
        identity.credentials().putAll(credentials);
        return engine.authenticate(identity, new HashMap<>());
    }

    private static String random(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
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
                    FakeRequest request = FakeRequest.of((HttpRequest) args[0]);
                    synchronized (sent) {
                        sent.add(request);
                    }
                    return exchange(request.proxy(), site.apply(request).proxy());
                });
        return (MontoyaApi) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "http" -> http;
                    case "logging" -> logging;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static HttpRequestResponse exchange(HttpRequest request, HttpResponse response) {
        return (HttpRequestResponse) Proxy.newProxyInstance(RecordedScriptsTest.class.getClassLoader(),
                new Class<?>[] { HttpRequestResponse.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "request" -> request;
                    case "response" -> response;
                    case "hasResponse" -> true;
                    case "copyToTempFile" -> proxy;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "toString" -> "exchange";
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    /** RFC 6238, the same parameters the generated script uses. */
    private static String totp(String base32) {
        try {
            String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            StringBuilder bits = new StringBuilder();
            for (char c : base32.toCharArray()) {
                String b = Integer.toBinaryString(alphabet.indexOf(c));
                bits.append("0".repeat(5 - b.length())).append(b);
            }
            byte[] key = new byte[bits.length() / 8];
            for (int i = 0; i < key.length; i++) {
                key[i] = (byte) Integer.parseInt(bits.substring(i * 8, i * 8 + 8), 2);
            }
            long counter = System.currentTimeMillis() / 1000L / 30;
            byte[] message = new byte[8];
            for (int i = 7; i >= 0; i--) {
                message[i] = (byte) (counter & 0xff);
                counter >>= 8;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(message);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            return String.format("%06d", binary % 1_000_000);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A request as the script built it. {@code withUpdatedHeader} follows the strict
     * Montoya reading -- it changes a present header and never adds a missing one
     * -- so a helper that relies on it to add Cookie or Content-Type fails here.
     */
    private record FakeRequest(String method, String url, Map<String, String> headers, String body) {

        static FakeRequest of(HttpRequest proxy) {
            return (FakeRequest) ((java.util.function.Supplier<?>) proxy).get();
        }

        boolean is(String m, String u) {
            return method.equals(m) && url.equals(u);
        }

        String header(String name) {
            return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                    .map(Map.Entry::getValue).findFirst().orElse(null);
        }

        String cookie(String name) {
            String header = header("Cookie");
            if (header == null) {
                return "";
            }
            for (String part : header.split(";\\s*")) {
                if (part.startsWith(name + "=")) {
                    return part.substring(name.length() + 1);
                }
            }
            return "";
        }

        Map<String, String> form() {
            Map<String, String> out = new LinkedHashMap<>();
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                }
            }
            return out;
        }

        private FakeRequest with(String m, String b, Map<String, String> h) {
            return new FakeRequest(m, url, h, b);
        }

        private Map<String, String> copyWithout(String name) {
            Map<String, String> copy = new LinkedHashMap<>(headers);
            copy.keySet().removeIf(k -> k.equalsIgnoreCase(name));
            return copy;
        }

        HttpRequest proxy() {
            return (HttpRequest) Proxy.newProxyInstance(RecordedScriptsTest.class.getClassLoader(),
                    new Class<?>[] { HttpRequest.class, java.util.function.Supplier.class },
                    (p, m, a) -> switch (m.getName()) {
                        case "get" -> this;
                        case "method" -> method;
                        case "url" -> url;
                        case "bodyToString" -> body;
                        case "headerValue" -> header((String) a[0]);
                        case "hasHeader" -> header((String) a[0]) != null;
                        case "withMethod" -> with((String) a[0], body, headers).proxy();
                        case "withBody" -> with(method, String.valueOf(a[0]), headers).proxy();
                        case "withUpdatedHeader" -> {
                            if (header((String) a[0]) == null) {
                                yield p;
                            }
                            Map<String, String> h = copyWithout((String) a[0]);
                            h.put((String) a[0], (String) a[1]);
                            yield with(method, body, h).proxy();
                        }
                        case "withAddedHeader" -> {
                            Map<String, String> h = copyWithout((String) a[0]);
                            h.put((String) a[0], (String) a[1]);
                            yield with(method, body, h).proxy();
                        }
                        case "withRemovedHeader" -> with(method, body, copyWithout((String) a[0])).proxy();
                        case "toString" -> method + " " + url;
                        case "hashCode" -> System.identityHashCode(p);
                        case "equals" -> p == a[0];
                        default -> throw new UnsupportedOperationException("request." + m.getName());
                    });
        }
    }

    private static final class FakeResponse {
        final int status;
        final String body;
        final List<String[]> headers = new ArrayList<>();
        final Map<String, String> cookies = new LinkedHashMap<>();

        FakeResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }

        static FakeResponse ok(String body) {
            return new FakeResponse(200, body);
        }

        FakeResponse header(String name, String value) {
            headers.add(new String[] { name, value });
            return this;
        }

        FakeResponse cookie(String name, String value) {
            cookies.put(name, value);
            return this;
        }

        HttpResponse proxy() {
            return (HttpResponse) Proxy.newProxyInstance(RecordedScriptsTest.class.getClassLoader(),
                    new Class<?>[] { HttpResponse.class },
                    (p, m, a) -> switch (m.getName()) {
                        case "statusCode" -> (short) status;
                        case "bodyToString" -> body;
                        case "headerValue" -> headers.stream().filter(h -> h[0].equalsIgnoreCase((String) a[0]))
                                .map(h -> h[1]).findFirst().orElse(null);
                        case "cookieValue" -> cookies.get((String) a[0]);
                        case "cookies" -> cookies.entrySet().stream().map(e -> cookieProxy(e.getKey(), e.getValue())).toList();
                        case "toString" -> "HTTP " + status;
                        case "hashCode" -> System.identityHashCode(p);
                        case "equals" -> p == a[0];
                        default -> throw new UnsupportedOperationException("response." + m.getName());
                    });
        }

        private static Cookie cookieProxy(String name, String value) {
            return (Cookie) Proxy.newProxyInstance(RecordedScriptsTest.class.getClassLoader(),
                    new Class<?>[] { Cookie.class },
                    (p, m, a) -> switch (m.getName()) {
                        case "name" -> name;
                        case "value" -> value;
                        default -> null;
                    });
        }
    }

    @SuppressWarnings("unused")
    private static String host(String url) {
        return URI.create(url).getHost();
    }
}
