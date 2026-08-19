/*
 * API reference for auth scripts -- NOT a template.
 *
 * The leading underscore keeps this file out of the jar's template list. It is
 * here to be read, and to give an editor something to resolve: with
 * burp-auth-check-<version>.jar on the project classpath, the declarations below
 * type-check and complete.
 *
 * Everything here is real. `AuthScriptBase` is the class your script is compiled
 * against at runtime, so its members are exactly the bindings you get.
 */

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.omnicybersecurity.authcheck.auth.ScriptHttp
import com.omnicybersecurity.authcheck.auth.ScriptLog

// ---------------------------------------------------------------------------
// Bindings. These exist in every script without declaring anything.
// ---------------------------------------------------------------------------

/** This identity's credential variables, from the Identities tab. */
Map<String, String> creds = [:]

/** HTTP helper. Requests go through Burp and show up in the Logger. */
ScriptHttp http = null

/** Survives between refreshes of this identity. Stash refresh tokens here. */
Map<String, String> vars = [:]

/** log.info / log.warn / log.error -- shown under the script and in Burp. */
ScriptLog log = null

/** The full Montoya API, for anything the helper does not cover. */
MontoyaApi api = null

/** This identity's display name. */
String identity = ''

// ---------------------------------------------------------------------------
// The http helper
// ---------------------------------------------------------------------------

HttpRequestResponse resp

// Sending. Redirects are NEVER followed unless you pass true, because a login's
// Set-Cookie usually arrives on the 302 and following it discards the session.
resp = http.get('https://target/path')
resp = http.get('https://target/path', ['Cookie': 'a=1'])
resp = http.postJson('https://target/login', [username: 'u', password: 'p'])
resp = http.postJson('https://target/login', [username: 'u'], ['X-Csrf': 't'])
resp = http.postForm('https://target/login', [username: 'u', password: 'p'])
resp = http.postForm('https://target/login', [username: 'u'], ['Cookie': 'a=1'])
resp = http.post('https://target/x', '<xml/>', 'application/xml')
resp = http.send(http.request('https://target/x').withMethod('POST'))
resp = http.send(http.request('https://target/x'), true)   // follow redirects

// Building a request to shape yourself. This is a Montoya HttpRequest, so every
// withXxx method on it is available.
HttpRequest built = http.request('https://target/api/session')
        .withMethod('POST')
        .withAddedHeader('Cookie', 'session=abc')
        .withAddedHeader('X-Tenant', 'acme')

// Reading responses.
short status = http.status(resp)
String body = http.body(resp)
Object parsed = http.json(resp)                    // maps and lists
String header = http.header(resp, 'Location')
String one = http.cookie(resp, 'JSESSIONID')       // a single Set-Cookie value
Map<String, String> all = http.cookies(resp)       // every cookie it set
String found = http.extractFrom(resp, /name="csrf" value="([^"]+)"/)
String fromText = http.extract(body, /token=(\w+)/)
String encoded = http.urlEncode('a value')

// ---------------------------------------------------------------------------
// What to return
// ---------------------------------------------------------------------------

// A bearer token.
//     return [headers: ['Authorization': "Bearer $token"]]
//
// A session cookie. NOTE the cookies: wrapper -- a bare map is applied as
// HEADERS, and http.cookies(resp) returns exactly that shape, so
// `return http.cookies(resp)` silently sets headers named after your cookies.
//     return [cookies: http.cookies(resp)]
//
// A cookie header string is split for you.
//     return [cookies: 'JSESSIONID=abc; csrf=xyz']
//
// A bare string goes into the identity's configured token header.
//     return "Bearer $token"
//
// A bare map with no recognised wrapper key is treated as headers.
//     return ['X-Api-Key': creds.token]
//
// Everything at once. params types: URL, BODY, COOKIE, JSON, XML,
// XML_ATTRIBUTE, MULTIPART_ATTRIBUTE.
//     return [
//         headers: ['Authorization': "Bearer $token"],
//         cookies: ['csrf': csrfCookie],
//         params : [[type: 'BODY', name: '_csrf', value: csrf]],
//         remove : ['If-None-Match']
//     ]

// ---------------------------------------------------------------------------
// Failing
// ---------------------------------------------------------------------------
//
// Throw. The message lands on the identity's status line and the affected rows
// read "Auth failed", instead of replaying with no credentials and reporting a
// bypass that is not real.
//
//     throw new IllegalStateException("Login failed: HTTP ${http.status(resp)}")
//
// Two things the engine treats as failure on your behalf:
//   - returning nothing usable, when the identity has no static headers either
//   - auth material whose values are all blank, which is what a lookup that
//     missed produces: sending "name=" looks authenticated and makes every
//     verdict downstream meaningless
