/*
 * Static session cookie
 *
 * No login flow: you already have a session cookie -- pasted out of the browser's
 * dev tools, or from a request in Proxy history -- and just want it applied to
 * every replayed request as this identity.
 *
 * Leave "Cookie" in the identity's "Strip these headers first" list, so the
 * captured request's own session is removed before this one is applied.
 *
 * Nothing here can refresh the value. When the application expires the session
 * you paste a new one, so there is no point setting an invalid-session pattern:
 * it would only make every request re-run this script and fail again. Use
 * "Test authentication now" after pasting to confirm the cookie is still good.
 *
 * For a session made of several cookies, or one paired with a CSRF cookie, use
 * "HTML form login -> session cookie" instead -- it hands back everything the
 * login set, and rebuilds it when it expires.
 */

params {
    param 'cookieName', type: STRING, required: true, label: 'Cookie name',
          help: 'e.g. JSESSIONID, session, PHPSESSID'
    param 'cookieValue', type: SECRET, required: true, label: 'Cookie value',
          help: 'The value only, without the name= prefix or any attributes'
}

def name = creds.cookieName.trim()
def value = creds.cookieValue.trim()

// Copying from dev tools tends to bring the whole pair, or a trailing "; Path=/"
// along with it. Both would be sent literally and look like a mangled session,
// so take the value the tester meant and say what was dropped.
if (value.startsWith("${name}=")) {
    value = value.substring(name.length() + 1)
    log.warn "Cookie value started with '${name}=' -- using the part after it"
}
if (value.contains(';')) {
    value = value.substring(0, value.indexOf(';')).trim()
    log.warn 'Cookie value contained attributes after a ";" -- using the value before it'
}

if (!value) {
    throw new IllegalStateException("Cookie value for '${name}' is empty after trimming")
}

log.info "Sending cookie '${name}' for ${identity} (${value.length()} chars)"

// The cookies: wrapper matters -- a bare map is applied as headers, which would
// set a header called JSESSIONID rather than a cookie.
return [cookies: [(name): value]]
