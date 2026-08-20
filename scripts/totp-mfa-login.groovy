/*
 * Login with a TOTP second factor
 *
 * Generates the six-digit code from the shared secret rather than asking you for
 * it, so an identity behind MFA can re-authenticate unattended -- which is the
 * whole point when sessions expire during a scan.
 *
 * Get the secret at enrolment time: the QR code encodes an otpauth:// URL whose
 * `secret` parameter is this value. Treat it as a password -- it is one.
 */

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

params {
    param 'base',       type: URL,    required: true, label: 'Base URL',
          help: 'e.g. https://target.example.com'
    param 'username',   type: STRING, required: true
    param 'password',   type: SECRET, required: true
    param 'totpSecret', type: SECRET, required: true, label: 'TOTP secret',
          help: 'The base32 secret from the enrolment QR code. Treat it as a password -- it is one'
}

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

// Step one: username and password.
def first = http.postJson("${creds.base}/login", [
        username: creds.username,
        password: creds.password
])

if (http.status(first) >= 400) {
    throw new IllegalStateException("Login failed: HTTP ${http.status(first)} ${http.body(first)}")
}

def carried = http.cookies(first)
def challenge = http.json(first)

// Step two: the second factor. Applications differ on whether the challenge is
// carried in a cookie, a token in the body, or both -- send whatever came back.
def code = totp(creds.totpSecret)
log.info "Submitting TOTP ${code} for ${creds.username}"

def headers = [:]
if (carried) {
    headers['Cookie'] = carried.collect { name, value -> "$name=$value" }.join('; ')
}

def second = http.postJson("${creds.base}/login/mfa",
        [code: code, challengeId: challenge?.challengeId],
        headers)

if (http.status(second) >= 400) {
    throw new IllegalStateException(
            "MFA step failed: HTTP ${http.status(second)} ${http.body(second)}. " +
            "If the code was rejected, check the clock skew on this machine.")
}

def session = http.cookies(second)
if (session) {
    carried.putAll(session)
    return [cookies: carried]
}

// Token-based instead of cookie-based.
def token = http.json(second).access_token
if (!token) {
    throw new IllegalStateException("MFA step returned neither a cookie nor a token")
}
return [headers: ['Authorization': "Bearer ${token}"]]
