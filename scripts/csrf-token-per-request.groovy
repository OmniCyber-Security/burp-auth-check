/*
 * Session cookie + CSRF token in the body
 *
 * Session cookie plus a CSRF token that has to go into the request body.
 *
 * Shows two things the simpler examples do not:
 *   - returning `params` so a token lands in a body/URL/JSON parameter rather
 *     than a header
 *   - returning several kinds of material at once
 *
 */

params {
    param 'base',     type: URL,    required: true, label: 'Base URL',
          help: 'e.g. https://target.example.com'
    param 'username', type: STRING, required: true
    param 'password', type: SECRET, required: true
}

def loginPage = http.get("${creds.base}/login")
def loginCsrf = http.extractFrom(loginPage, /name="_csrf"\s+value="([^"]+)"/)
def preSession = http.cookies(loginPage).collect { k, v -> "${k}=${v}" }.join('; ')

def login = http.postForm("${creds.base}/login",
        [username: creds.username, password: creds.password, _csrf: loginCsrf],
        preSession ? ['Cookie': preSession] : [:])

def cookies = http.cookies(login)
if (!cookies) {
    throw new IllegalStateException("Login set no cookies (HTTP ${http.status(login)})")
}

// Fetch a post-login page to get a CSRF token valid for the new session.
def cookieHeader = cookies.collect { k, v -> "${k}=${v}" }.join('; ')
def dashboard = http.get("${creds.base}/dashboard", ['Cookie': cookieHeader])
def sessionCsrf = http.extractFrom(dashboard, /name="_csrf"\s+value="([^"]+)"/)
        ?: http.header(dashboard, 'X-CSRF-Token')

if (!sessionCsrf) {
    log.warn 'No post-login CSRF token found; state-changing replays may be rejected'
}

log.info "Session established for ${creds.username}"

def material = [cookies: cookies]
if (sessionCsrf) {
    material.headers = ['X-CSRF-Token': sessionCsrf]
    // A parameter that already exists on the request is updated; one that does
    // not is added. Adding a BODY parameter to a GET makes no sense, so if the
    // target mixes both, narrow the identity's scope with the URL filters in
    // Settings, or drop `params` and rely on the header alone.
    material.params = [
        [type: 'BODY', name: '_csrf', value: sessionCsrf]
    ]
}

return material
