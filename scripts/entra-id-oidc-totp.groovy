/*
 * Entra ID (Azure AD) OIDC login with TOTP
 *
 * Entra ID stops issuing tokens through the password grant the moment MFA
 * applies to an account -- ROPC has nowhere to carry a second factor, so the
 * tenant answers AADSTS50076 and that is the end of it. This drives the
 * authorization-code flow the way a browser does instead: authorize, password,
 * the SAS second-factor endpoints, then the code exchange. The six-digit code is
 * generated from the enrolment secret, so the identity re-authenticates
 * unattended for the length of a scan.
 *
 * Credential variables expected on the identity:
 *   client_id     - the app registration this signs into
 *   redirect_uri  - a redirect URI registered on that app
 *   username      - the full UPN, e.g. tester@contoso.onmicrosoft.com
 *   password
 *   tenantId      - optional; the tenant GUID or domain. Set it for a
 *                   single-tenant app registration, which is most of them and
 *                   which rejects the shared endpoint with AADSTS50194. Leave it
 *                   unset only for a genuinely multi-tenant app, which signs in
 *                   through "organizations"
 *   totpSecret    - optional; the base32 secret from the enrolment QR code. Set
 *                   it whenever the account has MFA, which is the case this
 *                   script exists for. Without it, a tenant that asks for a
 *                   second factor fails the identity outright rather than
 *                   carrying on half-authenticated
 *   scope         - optional; defaults to "openid profile offline_access".
 *                   For an API, e.g. "api://<app-id>/.default offline_access"
 *   client_secret - optional; only for a confidential client
 *   authority     - optional; e.g. https://login.microsoftonline.us for GCC High
 *
 * Suggested "Session lifetime" settings:
 *   Session lifetime        : 3000, comfortably inside a default 60 minute token
 *   Invalid-session pattern : (?i)"error"\s*:\s*"invalid_token"
 *
 * What this cannot do, and it is better to know now than to debug it later:
 *   - Conditional Access that demands a compliant or hybrid-joined device, an
 *     approved client app, or number matching cannot be satisfied by a script.
 *     Test accounts need a scoped, documented exclusion, not a disabled policy.
 *   - The account must have a verification-code method enrolled (Authenticator's
 *     "verification code", or a third-party OATH token). A push-only or
 *     passwordless registration has no code for the script to type.
 *   - Federated accounts authenticate at their own IdP, not here; the script
 *     says so rather than failing obscurely.
 *   - These sign-ins land in the tenant's sign-in logs from an unfamiliar client
 *     and may raise risk detections. Tell whoever watches them first.
 *
 * Treat totpSecret exactly as you treat the password. It is one.
 */

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

['client_id', 'redirect_uri', 'username', 'password'].each { name ->
    if (!creds[name]) {
        throw new IllegalStateException("No '${name}' credential set on this identity")
    }
}

def authority = (creds.authority ?: 'https://login.microsoftonline.com').replaceAll('/+$', '')
// A tenant GUID or domain pins the flow to that one tenant; without it the
// shared "organizations" endpoint is used, which only a multi-tenant app accepts.
def tenant = creds.tenantId ?: 'organizations'
def scope = creds.scope ?: 'openid profile offline_access'
def clientId = creds.client_id
def redirectUri = creds.redirect_uri
def tokenUrl = "${authority}/${tenant}/oauth2/v2.0/token"

// Sign-in is a browser experience and Conditional Access rules key on that, so
// look like one throughout.
def USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

/** RFC 6238 TOTP, 6 digits, 30 second step, HMAC-SHA1. */
def totp = { String base32Secret ->
    // Decode base32 without padding, which is how enrolment secrets are printed.
    def alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    def cleaned = base32Secret.toUpperCase().replaceAll('[^A-Z2-7]', '')
    def bits = cleaned.collect { alphabet.indexOf(it as String) }
            .collect { String.format('%5s', Integer.toBinaryString(it)).replace(' ', '0') }
            .join('')
    def key = (0..<(bits.length().intdiv(8))).collect {
        Integer.parseInt(bits.substring(it * 8, it * 8 + 8), 2) as byte
    } as byte[]

    long counter = (System.currentTimeMillis() / 1000L).longValue().intdiv(30)
    def message = new byte[8]
    for (int i = 7; i >= 0; i--) {
        message[i] = (counter & 0xff) as byte
        counter >>= 8
    }

    def mac = Mac.getInstance('HmacSHA1')
    mac.init(new SecretKeySpec(key, 'HmacSHA1'))
    def hash = mac.doFinal(message)

    int offset = hash[hash.length - 1] & 0x0f
    int binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff)
    String.format('%06d', binary % 1_000_000)
}

// The flow spans eight or so hosts' worth of state on one host, and none of the
// helpers keep a cookie jar, so keep one here and send it on every hop.
def jar = [:]
def keep = { exchange -> jar.putAll(http.cookies(exchange)); exchange }
def headers = { Map extra = [:] ->
    def out = ['User-Agent': USER_AGENT,
               'Accept'    : 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8']
    if (jar) {
        out['Cookie'] = jar.collect { name, value -> "${name}=${value}" }.join('; ')
    }
    out.putAll(extra)
    out
}

def absolute = { String url ->
    if (!url) {
        return null
    }
    url.startsWith('http') ? url : authority + (url.startsWith('/') ? url : '/' + url)
}

/**
 * Every sign-in page carries a `$Config` JSON blob. Pull single fields out of it
 * rather than parsing the script block around it, which is not JSON.
 */
def field = { String html, String key ->
    def value = http.extract(html, '"' + key + '":"([^"]*)"')
    value == null ? null : value.replace('\\/', '/').replace('\\"', '"')
}

/** Entra will not redeem a SPA redirect URI without an Origin (AADSTS9002327). */
def origin = { String url -> http.extract(url, '^(https?://[^/]+)') ?: 'http://localhost' }

// ---------------------------------------------------------------------------
// The cheap path: the full sign-in is ten round trips, a refresh is one.
// ---------------------------------------------------------------------------

if (vars.refresh_token) {
    log.info 'Refreshing the existing access token'
    def form = [
            client_id    : clientId,
            grant_type   : 'refresh_token',
            refresh_token: vars.refresh_token,
            scope        : scope
    ]
    if (creds.client_secret) {
        form.client_secret = creds.client_secret
    }

    def refreshed = http.postForm(tokenUrl, form,
            ['User-Agent': USER_AGENT, 'Origin': origin(redirectUri)])

    if (http.status(refreshed) == 200) {
        def json = http.json(refreshed)
        if (json.refresh_token) {
            vars.refresh_token = json.refresh_token
        }
        log.info "Access token refreshed, expires_in=${json.expires_in}"
        return [headers: ['Authorization': "${json.token_type ?: 'Bearer'} ${json.access_token}"]]
    }

    log.warn "Refresh rejected (HTTP ${http.status(refreshed)}); signing in from the start"
    vars.remove('refresh_token')
}

// ---------------------------------------------------------------------------
// Step one: the authorization request, which serves the sign-in page.
// ---------------------------------------------------------------------------

// PKCE, because a public client without it is refused, and because the verifier
// has to survive to the exchange at the bottom of this script.
def verifier = (UUID.randomUUID().toString() + UUID.randomUUID().toString()).replace('-', '')
def challenge = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance('SHA-256').digest(verifier.getBytes('UTF-8')))
def state = UUID.randomUUID().toString()

def authorizeUrl = "${authority}/${tenant}/oauth2/v2.0/authorize" +
        '?client_id=' + http.urlEncode(clientId) +
        '&response_type=code' +
        '&redirect_uri=' + http.urlEncode(redirectUri) +
        '&response_mode=query' +
        '&scope=' + http.urlEncode(scope) +
        '&state=' + state +
        '&code_challenge=' + challenge +
        '&code_challenge_method=S256'

log.info "Starting the authorization-code flow for ${creds.username}"
def resp = keep(http.get(authorizeUrl, headers()))

// Tenant branding and home-realm discovery bounce a few times before the sign-in
// page itself. Stop at the redirect URI: that one carries the prize.
for (int hop = 0; hop < 5; hop++) {
    int status = http.status(resp)
    if (status < 300 || status >= 400) {
        break
    }
    def location = absolute(http.header(resp, 'Location'))
    if (!location || location.startsWith(redirectUri)) {
        break
    }
    resp = keep(http.get(location, headers(['Referer': authorizeUrl])))
}

def page = http.body(resp)
def flowToken = field(page, 'sFT')
def ctx = field(page, 'sCtx')
def canary = field(page, 'canary')
def apiCanary = field(page, 'apiCanary')
def urlPost = field(page, 'urlPost')

if (!flowToken || !ctx) {
    throw new IllegalStateException(
            "The sign-in page carried no flow token (HTTP ${http.status(resp)}). " +
            'Conditional Access blocking the request outright looks like this, and so ' +
            'does a federated tenant handing off to its own IdP -- read the response ' +
            'in the Logger before changing anything here.')
}

// ---------------------------------------------------------------------------
// Step two: who is this? Advisory, but it names a federated account before the
// password POST fails obscurely, and it moves the flow token on.
// ---------------------------------------------------------------------------

def credentialTypeUrl = absolute(field(page, 'urlGetCredentialType')) ?:
        "${authority}/common/GetCredentialType?mkt=en-US"

def credentialType = keep(http.postJson(credentialTypeUrl, [
        username            : creds.username,
        isOtherIdpSupported : true,
        checkPhonePassword  : false,
        isRemoteNGCSupported: true,
        isCookieBannerShown : false,
        isFidoSupported     : true,
        originalRequest     : ctx,
        flowToken           : flowToken
], headers(['Referer': authorizeUrl, 'canary': apiCanary ?: ''])))

if (http.status(credentialType) == 200) {
    def credential = http.json(credentialType)
    if (credential?.Credentials?.FederationRedirectUrl) {
        throw new IllegalStateException(
                "${creds.username} is federated to ${credential.Credentials.FederationRedirectUrl}. " +
                'The password and the second factor are handled there, not by Entra ID; ' +
                'point this script at that IdP instead.')
    }
    if (credential?.IfExistsResult == 1) {
        log.warn "Entra ID does not recognise ${creds.username} in tenant ${tenant}"
    }
    if (credential?.FlowToken) {
        flowToken = credential.FlowToken
    }
} else {
    log.warn "GetCredentialType returned HTTP ${http.status(credentialType)}; carrying on regardless"
}

// ---------------------------------------------------------------------------
// Step three: the password.
// ---------------------------------------------------------------------------

def loginUrl = absolute(urlPost) ?: "${authority}/${tenant}/login"
def login = keep(http.postForm(loginUrl, [
        login       : creds.username,
        loginfmt    : creds.username,
        passwd      : creds.password,
        ctx         : ctx,
        flowToken   : flowToken,
        canary      : canary ?: '',
        type        : '11',
        LoginOptions: '3',
        NewUser     : '1',
        PPSX        : '',
        fspost      : '0',
        i13         : '0'
], headers(['Referer': authorizeUrl])))

page = http.body(login)

// 50126 is a wrong password, 50053 a locked account, 50055 an expired one. The
// page states which in prose, so pass that on rather than the number.
def signInError = field(page, 'sErrTxt')
if (signInError) {
    throw new IllegalStateException("Password step rejected: ${signInError}")
}

flowToken = field(page, 'sFT') ?: flowToken
ctx = field(page, 'sCtx') ?: ctx
canary = field(page, 'canary') ?: canary
apiCanary = field(page, 'apiCanary') ?: apiCanary
urlPost = field(page, 'urlPost') ?: urlPost
resp = login

// ---------------------------------------------------------------------------
// Step four: the second factor, if the tenant asked for one.
// ---------------------------------------------------------------------------

def beginAuthUrl = absolute(field(page, 'urlBeginAuth'))

if (!beginAuthUrl) {
    // Nothing to fail on here -- but say so loudly, because an identity set up
    // for MFA that is never challenged is usually a sign the wrong account,
    // tenant or app registration is in play.
    log.warn 'Entra ID asked for no second factor; the password alone satisfied this sign-in'
} else if (!creds.totpSecret) {
    throw new IllegalStateException(
            "Entra ID asked for a second factor and this identity has no 'totpSecret' " +
            'set, so the sign-in cannot be completed. Add the base32 secret from the ' +
            'enrolment QR code to the identity. Failing here is deliberate: replaying ' +
            'without credentials would report a bypass that is not real.')
} else {
    def endAuthUrl = absolute(field(page, 'urlEndAuth')) ?: beginAuthUrl.replace('BeginAuth', 'EndAuth')
    def code = totp(creds.totpSecret)
    log.info "Submitting TOTP ${code} for ${creds.username}"

    def sasHeaders = headers([
            'Referer'          : loginUrl,
            'canary'           : apiCanary ?: '',
            'client-request-id': UUID.randomUUID().toString()
    ])

    def begunResp = keep(http.postJson(beginAuthUrl, [
            AuthMethodId: 'PhoneAppOTP',
            Method      : 'BeginAuth',
            ctx         : ctx,
            flowToken   : flowToken
    ], sasHeaders))

    if (http.status(begunResp) != 200) {
        throw new IllegalStateException(
                "BeginAuth failed: HTTP ${http.status(begunResp)} ${http.body(begunResp)}")
    }

    def begun = http.json(begunResp)
    if (!begun?.Success) {
        throw new IllegalStateException(
                "Entra ID would not start the second factor: ${begun?.Message ?: begun}. " +
                'PhoneAppOTP needs a verification-code method enrolled on the account -- a ' +
                'push-only or passwordless registration has no code to type.')
    }

    def endedResp = keep(http.postJson(endAuthUrl, [
            Method            : 'EndAuth',
            SessionId         : begun.SessionId,
            FlowToken         : begun.FlowToken,
            Ctx               : begun.Ctx,
            AuthMethodId      : 'PhoneAppOTP',
            AdditionalAuthData: code,
            PollCount         : 1
    ], sasHeaders))

    if (http.status(endedResp) != 200) {
        throw new IllegalStateException(
                "EndAuth failed: HTTP ${http.status(endedResp)} ${http.body(endedResp)}")
    }

    def ended = http.json(endedResp)
    if (!ended?.Success || !'SUCCESS'.equalsIgnoreCase(String.valueOf(ended?.ResultValue))) {
        throw new IllegalStateException(
                "TOTP rejected: ${ended?.ResultValue ?: ended?.Message}. If the code was well " +
                'formed, check the clock on this machine -- a 30 second step leaves no room ' +
                'for drift.')
    }

    flowToken = ended.FlowToken ?: flowToken
    ctx = ended.Ctx ?: ctx

    // The SAS calls only prove the code. ProcessAuth is the ordinary form post
    // that turns a proven factor into a session.
    resp = keep(http.postForm(absolute(urlPost) ?: "${authority}/common/SAS/ProcessAuth", [
            type         : '19',
            request      : ctx,
            mfaAuthMethod: 'PhoneAppOTP',
            otc          : code,
            login        : creds.username,
            flowToken    : flowToken,
            canary       : canary ?: '',
            rememberMFA  : 'false'
    ], headers(['Referer': loginUrl])))

    page = http.body(resp)
    flowToken = field(page, 'sFT') ?: flowToken
    ctx = field(page, 'sCtx') ?: ctx
    canary = field(page, 'canary') ?: canary
    urlPost = field(page, 'urlPost') ?: urlPost
}

// ---------------------------------------------------------------------------
// Step five: clear the interstitials and collect the authorization code.
// ---------------------------------------------------------------------------

def authCode = null

for (int hop = 0; hop < 5 && !authCode; hop++) {
    int status = http.status(resp)

    if (status >= 300 && status < 400) {
        def location = http.header(resp, 'Location')
        def found = http.extract(location, '[?&]code=([^&]+)')
        if (!found) {
            def described = http.extract(location, '[?&]error_description=([^&]+)')
            throw new IllegalStateException(
                    "Sign-in redirected without a code: ${described ? URLDecoder.decode(described, 'UTF-8') : location}")
        }
        authCode = URLDecoder.decode(found, 'UTF-8')
        break
    }

    page = http.body(resp)

    // response_mode=form_post arrives as a self-submitting form instead.
    authCode = http.extract(page, 'name="code" value="([^"]+)"')
    if (authCode) {
        break
    }

    def stopped = field(page, 'sErrTxt')
    if (stopped) {
        throw new IllegalStateException("Sign-in stopped: ${stopped}")
    }

    def next = absolute(field(page, 'urlPost'))
    if (!next) {
        throw new IllegalStateException(
                "Sign-in ended with no code and no next step (HTTP ${status}). An unhandled " +
                'interrupt -- a password change, an MFA registration prompt, terms of use -- ' +
                'looks like this. Read the page in the Logger.')
    }

    // "Stay signed in?" and its siblings are all the same shape: post the flow
    // token back and carry on.
    log.info "Clearing an interstitial at ${next}"
    resp = keep(http.postForm(next, [
            LoginOptions: '1',
            type        : '28',
            ctx         : ctx,
            flowToken   : flowToken,
            canary      : canary ?: '',
            hpgrequestid: ''
    ], headers(['Referer': loginUrl])))

    page = http.body(resp)
    ctx = field(page, 'sCtx') ?: ctx
    flowToken = field(page, 'sFT') ?: flowToken
    canary = field(page, 'canary') ?: canary
}

if (!authCode) {
    throw new IllegalStateException('Sign-in finished without producing an authorization code')
}

// ---------------------------------------------------------------------------
// Step six: redeem the code.
// ---------------------------------------------------------------------------

def form = [
        client_id    : clientId,
        grant_type   : 'authorization_code',
        code         : authCode,
        redirect_uri : redirectUri,
        code_verifier: verifier,
        scope        : scope
]
if (creds.client_secret) {
    form.client_secret = creds.client_secret
}

def tokenResponse = http.postForm(tokenUrl, form,
        ['User-Agent': USER_AGENT, 'Origin': origin(redirectUri)])

if (http.status(tokenResponse) != 200) {
    throw new IllegalStateException(
            "Token exchange failed: HTTP ${http.status(tokenResponse)} ${http.body(tokenResponse)}")
}

def tokens = http.json(tokenResponse)
if (!tokens.access_token) {
    throw new IllegalStateException("No access_token in the token response: ${http.body(tokenResponse)}")
}

// Keep the refresh token so the next refresh skips everything above it.
if (tokens.refresh_token) {
    vars.refresh_token = tokens.refresh_token
}

log.info "Signed in as ${creds.username}, expires_in=${tokens.expires_in}"

return [
    headers: ['Authorization': "${tokens.token_type ?: 'Bearer'} ${tokens.access_token}"],
    vars   : [expires_in: String.valueOf(tokens.expires_in)]
]

// If the target is a server-rendered application rather than an API, the code is
// redeemed by the application, and what you want is the cookie it sets. Delete
// the exchange above and hand the callback over instead:
//
//     def callback = keep(http.get(
//             "${redirectUri}?code=${http.urlEncode(authCode)}&state=${state}",
//             headers(['Referer': authority + '/'])))
//     def session = http.cookies(callback)
//     if (!session) {
//         throw new IllegalStateException(
//                 "The callback set no session cookie: HTTP ${http.status(callback)}")
//     }
//     return [cookies: session]
