/*
 * Login, then assume a role
 *
 * Two-step authentication: log in, then call a second endpoint that elevates or
 * switches the session to a particular role. Common in applications where one
 * account can act as several personas, which is exactly the shape an
 * authorisation test wants -- one identity per role, same underlying account.
 *
 * The two things worth copying here:
 *
 *   1. The role call's response is checked. A 403 from it means the session is
 *      NOT the role you think it is, and every verdict that follows would be
 *      measuring the wrong user.
 *
 *   2. Whatever the role call sets is merged over the login cookies. Some
 *      applications rotate the session on a privilege change (good practice,
 *      and correct); others elevate in place. Merging handles both without
 *      caring which this one does.
 */

params {
    param 'base',     type: URL,    required: true, label: 'Base URL',
          help: 'e.g. https://target.example.com'
    param 'username', type: STRING, required: true
    param 'password', type: SECRET, required: true
    param 'roleId',   type: STRING, required: true, label: 'Role to assume',
          help: 'One identity per role, same underlying account'
}

def resp = http.postJson("${creds.base}/login", [
        username: creds.username,
        password: creds.password
])

if (http.status(resp) != 200) {
    throw new IllegalStateException("Login failed: HTTP ${http.status(resp)} ${http.body(resp)}")
}

// Keep every cookie the login set, not just the session one: antiforgery and
// load-balancer affinity cookies usually have to be sent alongside it.
def jar = http.cookies(resp)
if (!jar) {
    throw new IllegalStateException("Login set no cookies (HTTP ${http.status(resp)})")
}
log.info "Logged in as ${creds.username}, cookies: ${jar.keySet()}"

def assume = http.send(
        http.request("${creds.base}/api/authorisation/roles/assume/${creds.roleId}")
            .withMethod('POST')
            .withAddedHeader('Cookie', jar.collect { name, value -> "$name=$value" }.join('; ')))

if (http.status(assume) >= 400) {
    throw new IllegalStateException(
            "Assuming role ${creds.roleId} failed: HTTP ${http.status(assume)} ${http.body(assume)}")
}

def rotated = http.cookies(assume)
if (rotated) {
    log.info "Role assumption re-issued: ${rotated.keySet()}"
    jar.putAll(rotated)
} else {
    log.info 'Role assumption set no cookies; the existing session was elevated in place'
}

return [cookies: jar]
