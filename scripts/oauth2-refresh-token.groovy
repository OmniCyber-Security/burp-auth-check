/*
 * OAuth2 password grant that reuses its refresh token.
 *
 * This is the pattern for applications whose access tokens die in a minute or
 * two: the full login runs once, and every refresh after that is a cheap
 * refresh_token exchange. `vars` is the per-identity map that survives between
 * refreshes, which is what makes it possible.
 *
 * Credential variables expected on the identity:
 *   base          - e.g. https://target.example.com
 *   client_id
 *   client_secret - optional
 *   username
 *   password
 *
 * Suggested "Session lifetime" settings:
 *   Session lifetime        : slightly under the token's expires_in, e.g. 240 for a 300s token
 *   Invalid-session pattern : (?i)"error"\s*:\s*"invalid_token"
 */

def tokenUrl = "${creds.base}/oauth/token"
def resp = null

if (vars.refresh_token) {
    log.info 'Refreshing the existing access token'
    def form = [
            grant_type   : 'refresh_token',
            refresh_token: vars.refresh_token,
            client_id    : creds.client_id
    ]
    if (creds.client_secret) {
        form.client_secret = creds.client_secret
    }
    resp = http.postForm(tokenUrl, form)

    if (http.status(resp) != 200) {
        log.warn "Refresh rejected (HTTP ${http.status(resp)}); falling back to a full login"
        vars.remove('refresh_token')
        resp = null
    }
}

if (resp == null) {
    log.info "Performing a full password-grant login as ${creds.username}"
    def form = [
            grant_type: 'password',
            username  : creds.username,
            password  : creds.password,
            client_id : creds.client_id
    ]
    if (creds.client_secret) {
        form.client_secret = creds.client_secret
    }
    resp = http.postForm(tokenUrl, form)
}

if (http.status(resp) != 200) {
    throw new IllegalStateException("Token request failed: HTTP ${http.status(resp)} ${http.body(resp)}")
}

def json = http.json(resp)
if (!json.access_token) {
    throw new IllegalStateException("No access_token in the token response: ${http.body(resp)}")
}

// Keep the refresh token for next time; this is the whole point of `vars`.
if (json.refresh_token) {
    vars.refresh_token = json.refresh_token
}

log.info "Access token acquired, expires_in=${json.expires_in}"

return [
    headers: ['Authorization': "${json.token_type ?: 'Bearer'} ${json.access_token}"],
    vars   : [expires_in: String.valueOf(json.expires_in)]
]
