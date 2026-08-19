/*
 * Classic HTML form login: fetch the login page for its CSRF token, post the
 * credentials, keep the session cookie.
 *
 * Credential variables expected on the identity:
 *   base      - e.g. https://target.example.com
 *   username
 *   password
 *
 * Because the session lives in a cookie, leave "Cookie" in the identity's
 * "Strip these headers first" list so the baseline user's session is removed
 * before this one is applied.
 *
 * Suggested "Session lifetime" settings:
 *   Invalid-session pattern : (?i)(please log in|session (has )?expired|<form[^>]*id="login")
 *   Session-check URL       : https://target.example.com/account
 *   Healthy-session pattern : (?i)signed in as
 */

// 1. The login page carries the CSRF token and usually a pre-session cookie.
def loginPage = http.get("${creds.base}/login")
if (http.status(loginPage) >= 400) {
    throw new IllegalStateException("Could not load the login page: HTTP ${http.status(loginPage)}")
}

def csrf = http.extractFrom(loginPage, /name="(?:csrf_token|_csrf|authenticity_token)"\s+value="([^"]+)"/)
if (!csrf) {
    log.warn 'No CSRF token found on the login page; posting without one'
}

// 2. Carry the pre-session cookies into the POST -- many frameworks tie the
//    CSRF token to that cookie and reject the login without it.
def preSession = http.cookies(loginPage)
def cookieHeader = preSession.collect { name, value -> "${name}=${value}" }.join('; ')

def form = [username: creds.username, password: creds.password]
if (csrf) {
    form.csrf_token = csrf
}

def resp = http.postForm("${creds.base}/login", form,
        cookieHeader ? ['Cookie': cookieHeader] : [:])

// 3. The session cookie normally arrives on the 302 that follows a good login,
//    which is why redirects are not followed by default.
def cookies = http.cookies(resp)
log.info "Login returned HTTP ${http.status(resp)}, set: ${cookies.keySet()}"

def sessionName = cookies.keySet().find { it =~ /(?i)(session|sid|auth)/ }
if (!sessionName) {
    throw new IllegalStateException(
            "No session cookie in the login response (HTTP ${http.status(resp)}). " +
            "Body started: ${http.body(resp).take(200)}")
}

log.info "Logged in as ${creds.username}, session cookie '${sessionName}'"

// Hand back every cookie the login set: some apps pair the session with a
// separate CSRF cookie that later requests also need.
return [cookies: cookies]
