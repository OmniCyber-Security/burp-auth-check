package com.omnicybersecurity.authcheck.ui;

import java.util.LinkedHashMap;
import java.util.Map;

/** Starter auth scripts, offered from the Identities panel. */
public final class ScriptTemplates {

    private ScriptTemplates() {
    }

    public static final String JSON_LOGIN = """
            // JSON login returning a bearer token.
            // Credentials come from this identity's credential table.
            def resp = http.postJson('https://target.example.com/api/login', [
                    username: creds.username,
                    password: creds.password
            ])

            if (http.status(resp) != 200) {
                throw new IllegalStateException("Login failed: HTTP ${http.status(resp)} ${http.body(resp)}")
            }

            def token = http.json(resp).access_token
            log.info "Got a token ending ...${token[-6..-1]}"

            return [headers: ['Authorization': "Bearer ${token}"]]
            """;

    public static final String FORM_LOGIN_COOKIE = """
            // Classic form login: capture the session cookie, carrying the CSRF
            // token from the login page through the POST.
            def loginPage = http.get('https://target.example.com/login')
            def csrf = http.extractFrom(loginPage, /name="csrf_token"\\s+value="([^"]+)"/)
            def initialCookies = http.cookies(loginPage)

            def resp = http.postForm('https://target.example.com/login',
                    [username: creds.username, password: creds.password, csrf_token: csrf],
                    ['Cookie': initialCookies.collect { k, v -> "$k=$v" }.join('; ')])

            def session = http.cookie(resp, 'JSESSIONID')
            if (!session) {
                throw new IllegalStateException("No session cookie in the login response (HTTP ${http.status(resp)})")
            }
            log.info "Logged in as ${creds.username}"

            return [cookies: ['JSESSIONID': session]]
            """;

    public static final String OAUTH_REFRESH = """
            // OAuth2 password grant that reuses its refresh token.
            // `vars` persists between refreshes for exactly this purpose.
            def tokenUrl = 'https://target.example.com/oauth/token'
            def resp

            if (vars.refresh_token) {
                log.info 'Refreshing the existing token'
                resp = http.postForm(tokenUrl, [
                        grant_type   : 'refresh_token',
                        refresh_token: vars.refresh_token,
                        client_id    : creds.client_id
                ])
                if (http.status(resp) != 200) {
                    log.warn 'Refresh rejected; falling back to a full login'
                    vars.remove('refresh_token')
                    resp = null
                }
            }

            if (resp == null) {
                resp = http.postForm(tokenUrl, [
                        grant_type: 'password',
                        username  : creds.username,
                        password  : creds.password,
                        client_id : creds.client_id
                ])
            }

            if (http.status(resp) != 200) {
                throw new IllegalStateException("Token request failed: HTTP ${http.status(resp)} ${http.body(resp)}")
            }

            def json = http.json(resp)
            if (json.refresh_token) {
                vars.refresh_token = json.refresh_token
            }
            log.info "Token valid for ${json.expires_in}s"

            return [
                headers: ['Authorization': "Bearer ${json.access_token}"],
                vars   : [expires_in: String.valueOf(json.expires_in)]
            ]
            """;

    public static final String STATIC_TOKEN = """
            // No login flow: just present a token stored in the credential table.
            // Useful for API keys, or when you paste a token grabbed by hand.
            return [headers: ['Authorization': "Bearer ${creds.token}"]]
            """;

    public static Map<String, String> all() {
        Map<String, String> templates = new LinkedHashMap<>();
        templates.put("JSON login -> bearer token", JSON_LOGIN);
        templates.put("Form login -> session cookie", FORM_LOGIN_COOKIE);
        templates.put("OAuth2 with refresh token", OAUTH_REFRESH);
        templates.put("Static token / API key", STATIC_TOKEN);
        return templates;
    }
}
