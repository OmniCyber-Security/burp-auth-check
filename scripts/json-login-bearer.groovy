/*
 * JSON login that returns a bearer token.
 *
 * Credential variables expected on the identity:
 *   base      - e.g. https://target.example.com
 *   username
 *   password
 *
 * Suggested "Session lifetime" settings for a short-lived token:
 *   Session lifetime        : whatever the token's expires_in says, e.g. 300
 *   Invalid-session pattern : (?i)"(error|message)"\s*:\s*"(invalid|expired)_?token"
 */

def resp = http.postJson("${creds.base}/api/v1/login", [
        username: creds.username,
        password: creds.password
])

if (http.status(resp) != 200) {
    // Throwing marks the identity's rows "Auth failed" instead of quietly
    // replaying without credentials and inventing a bypass.
    throw new IllegalStateException("Login failed: HTTP ${http.status(resp)} ${http.body(resp)}")
}

def json = http.json(resp)
def token = json.access_token ?: json.token ?: json.data?.accessToken
if (!token) {
    throw new IllegalStateException("No token field in the login response: ${http.body(resp)}")
}

// Surface the lifetime in the UI so you can set the session lifetime to match.
if (json.expires_in) {
    log.info "Token valid for ${json.expires_in}s"
}

return [
    headers: ['Authorization': "Bearer ${token}"],
    vars   : [expires_in: String.valueOf(json.expires_in)]
]
