// Synthetic captures, shaped exactly like what the recorder saves. Each one is a
// login pattern the generator has to get right, padded with the noise a real
// page makes (analytics, assets, pre-existing cookies) that it has to ignore.

let seq = 0;
const ex = (method, url, { req = {}, body = null, status = 200, res = {}, resBody = null,
  type = 'Document', mime = 'text/html', from = null } = {}) => {
  seq += 1;
  const toList = (object) => Object.entries(object).flatMap(([name, value]) =>
    (Array.isArray(value) ? value.map((v) => [name, v]) : [[name, value]]));
  return {
    id: `x${seq}`,
    seq,
    time: 1_760_000_000_000 + seq * 1000,
    method,
    url,
    resourceType: type,
    requestHeaders: toList({
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/142.0',
      'Accept-Language': 'en-GB,en;q=0.9',
      Accept: type === 'Document' ? 'text/html,application/xhtml+xml' : 'application/json',
      'Sec-Fetch-Mode': type === 'Document' ? 'navigate' : 'cors',
      ...req,
    }),
    requestBody: body,
    status,
    statusText: '',
    responseHeaders: toList({ 'Content-Type': mime, ...res }),
    responseBody: resBody,
    responseBodyBase64: false,
    mimeType: mime,
    redirectedFrom: from,
    failed: null,
    fromCache: false,
  };
};

const input = (fields) => fields.map((f, i) => ({
  name: '', id: '', type: 'text', autocomplete: '', placeholder: '', label: '',
  reason: 'submit', url: '', time: 1_760_000_000_000 + i, ...f,
}));

export function formLogin() {
  seq = 0;
  const loginPage = ex('GET', 'https://app.example.com/login', {
    req: { Cookie: '_ga=GA1.2.111' },
    res: { 'Set-Cookie': ['pre_session=p1a2b3c4d5; Path=/; HttpOnly'] },
    resBody: `<html><form method="post" action="/login">
      <input type="hidden" name="_csrf" value="Tq9-csrf-7781xYz">
      <input name="username"><input type="password" name="password"></form></html>`,
  });
  const css = ex('GET', 'https://app.example.com/static/site.css', { type: 'Stylesheet', mime: 'text/css' });
  const analytics = ex('GET', 'https://analytics.example.net/collect?cid=8842119911&page=login', {
    type: 'Other', mime: 'image/gif',
  });
  const login = ex('POST', 'https://app.example.com/login', {
    req: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'https://app.example.com',
      Referer: 'https://app.example.com/login',
      Cookie: '_ga=GA1.2.111; pre_session=p1a2b3c4d5',
    },
    body: '_csrf=Tq9-csrf-7781xYz&username=alice%40example.com&password=s3cret%21pw',
    status: 302,
    res: { Location: '/dashboard', 'Set-Cookie': ['SESSION=sess-0a9f8e7d6c; Path=/; HttpOnly; Secure'] },
  });
  const dashboard = ex('GET', 'https://app.example.com/dashboard', {
    req: { Cookie: '_ga=GA1.2.111; pre_session=p1a2b3c4d5; SESSION=sess-0a9f8e7d6c' },
    from: login.id,
    resBody: '<html>Signed in as alice</html>',
  });
  const me = ex('GET', 'https://app.example.com/api/me', {
    type: 'XHR', mime: 'application/json',
    req: { Cookie: '_ga=GA1.2.111; pre_session=p1a2b3c4d5; SESSION=sess-0a9f8e7d6c' },
    resBody: '{"user":"alice"}',
  });
  // The redirect hop shares the login's requestId, which is how the recorder
  // links them; the analyser relies on redirectedFrom.
  return {
    id: 'cap-form', title: 'Form login with CSRF', tabUrl: 'https://app.example.com/login',
    startedAt: 1_760_000_000_000,
    exchanges: [loginPage, css, analytics, login, dashboard, me],
    inputs: input([
      { name: 'username', type: 'email', value: 'alice@example.com' },
      { name: 'password', type: 'password', value: 's3cret!pw' },
      { name: 'q', type: 'search', value: 'unrelated search', reason: 'change' },
    ]),
  };
}

export function jsonBearer() {
  seq = 0;
  const shell = ex('GET', 'https://api.example.com/app', { resBody: '<html><div id="root"></div></html>' });
  const config = ex('GET', 'https://api.example.com/api/config', {
    type: 'Fetch', mime: 'application/json', resBody: '{"clientVersion":"2.4.1","feature":"x"}',
  });
  const login = ex('POST', 'https://api.example.com/api/auth/login', {
    type: 'Fetch', mime: 'application/json',
    req: { 'Content-Type': 'application/json', 'X-Client-Version': '2.4.1', Origin: 'https://api.example.com' },
    body: JSON.stringify({ email: 'bob@example.com', password: 'hunter2!!', remember: true }),
    resBody: JSON.stringify({ data: { accessToken: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.sig4567890', expiresIn: 300 } }),
  });
  const profile = ex('GET', 'https://api.example.com/api/profile', {
    type: 'Fetch', mime: 'application/json',
    req: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.sig4567890', 'X-Client-Version': '2.4.1' },
    resBody: '{"name":"Bob"}',
  });
  return {
    id: 'cap-json', title: 'JSON login to bearer token', tabUrl: 'https://api.example.com/app',
    startedAt: 1_760_000_000_000,
    exchanges: [shell, config, login, profile],
    inputs: input([
      { name: 'email', type: 'email', value: 'bob@example.com' },
      { name: 'password', type: 'password', value: 'hunter2!!' },
    ]),
  };
}

export function oidcTotp() {
  seq = 0;
  const start = ex('GET', 'https://app.example.com/', {
    status: 302,
    res: { Location: 'https://idp.example.org/auth?client_id=portal&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&state=St4te-99xQ' },
  });
  const authorize = ex('GET', 'https://idp.example.org/auth?client_id=portal&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&state=St4te-99xQ', {
    from: start.id,
    res: { 'Set-Cookie': ['AUTH_SESSION_ID=as-77c1e2f3a4; Path=/; Secure'] },
    resBody: `<html><form id="kc-form-login" action="https://idp.example.org/login-actions/authenticate?session_code=Sc0de-1a2b3c&amp;execution=exec-998877&amp;tab_id=Tab4x2" method="post">
      <input name="username"><input name="password" type="password"></form></html>`,
  });
  const password = ex('POST', 'https://idp.example.org/login-actions/authenticate?session_code=Sc0de-1a2b3c&execution=exec-998877&tab_id=Tab4x2', {
    req: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: 'AUTH_SESSION_ID=as-77c1e2f3a4', Origin: 'null' },
    body: 'username=carol&password=Pa%24%24w0rd-long&credentialId=',
    res: {},
    resBody: `<html><form id="kc-otp-login-form" action="https://idp.example.org/login-actions/authenticate?session_code=Sc0de-4d5e6f&amp;execution=otp-112233&amp;tab_id=Tab4x2" method="post">
      <input id="otp" name="otp" autocomplete="one-time-code"></form></html>`,
  });
  const otp = ex('POST', 'https://idp.example.org/login-actions/authenticate?session_code=Sc0de-4d5e6f&execution=otp-112233&tab_id=Tab4x2', {
    req: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: 'AUTH_SESSION_ID=as-77c1e2f3a4' },
    body: 'otp=482913&login=Sign+In',
    status: 302,
    res: { Location: 'https://app.example.com/cb?state=St4te-99xQ&code=c0de-5f6e7d8c9b' },
  });
  const callback = ex('GET', 'https://app.example.com/cb?state=St4te-99xQ&code=c0de-5f6e7d8c9b', {
    from: otp.id,
    status: 302,
    res: { Location: '/', 'Set-Cookie': ['portal_sid=ps-aa11bb22cc33; Path=/; HttpOnly'] },
  });
  const home = ex('GET', 'https://app.example.com/', {
    from: callback.id, req: { Cookie: 'portal_sid=ps-aa11bb22cc33' }, resBody: '<html>Welcome</html>',
  });
  const user = ex('GET', 'https://app.example.com/api/user', {
    type: 'XHR', mime: 'application/json', req: { Cookie: 'portal_sid=ps-aa11bb22cc33' }, resBody: '{"sub":"carol"}',
  });
  return {
    id: 'cap-oidc', title: 'Keycloak sign-in with TOTP', tabUrl: 'https://app.example.com/',
    startedAt: 1_760_000_000_000,
    exchanges: [start, authorize, password, otp, callback, home, user],
    inputs: input([
      { name: 'username', value: 'carol' },
      { name: 'password', type: 'password', value: 'Pa$$w0rd-long' },
      { name: 'otp', id: 'otp', autocomplete: 'one-time-code', value: '482913' },
    ]),
  };
}

// The awkward cases together: two hosts setting a cookie of the same name, a
// JSON body sent as text/plain (fetch's default), a numeric one-time code,
// fields named after Groovy keywords, and a token after a no-break space.
export function ssoEdgeCases() {
  seq = 0;
  const start = ex('GET', 'https://app.example.com/start', {
    status: 302,
    res: {
      Location: 'https://sso.example.org/login?goto=https%3A%2F%2Fapp.example.com%2Fsso%2Fcallback',
      'Set-Cookie': ['JSESSIONID=app-11aa22bb33; Path=/; HttpOnly'],
    },
  });
  const login = ex('GET', 'https://sso.example.org/login?goto=https%3A%2F%2Fapp.example.com%2Fsso%2Fcallback', {
    from: start.id,
    res: { 'Set-Cookie': ['JSESSIONID=sso-44cc55dd66; Path=/; Secure'] },
    resBody: `<html><form><input type="hidden" name="continue" value="Cnt-778899aa">
      <p>Request ref:\u00a0Rf-55aa66bb77</p></form></html>`,
  });
  const authenticate = ex('POST', 'https://sso.example.org/api/authenticate', {
    type: 'Fetch', mime: 'application/json',
    req: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'X-Request-Ref': 'Rf-55aa66bb77',
      Cookie: 'JSESSIONID=sso-44cc55dd66',
    },
    body: JSON.stringify({ user: 'gina@example.com', pass: 'Gina-pass-123', otp: 482913, continue: 'Cnt-778899aa' }),
    resBody: JSON.stringify({ goto: 'https://app.example.com/sso/callback?ticket=Tk-0099887766' }),
  });
  const callback = ex('GET', 'https://app.example.com/sso/callback?ticket=Tk-0099887766', {
    req: { Cookie: 'JSESSIONID=app-11aa22bb33' },
    status: 302,
    res: { Location: '/home', 'Set-Cookie': ['APPSESSION=as-1234567890; Path=/; HttpOnly'] },
  });
  const home = ex('GET', 'https://app.example.com/home', {
    from: callback.id,
    req: { Cookie: 'JSESSIONID=app-11aa22bb33; APPSESSION=as-1234567890' },
    resBody: '<html>Hello Gina</html>',
  });
  return {
    id: 'cap-sso', title: 'Sign in */ System.exit(1) /* ', tabUrl: 'https://app.example.com/start',
    startedAt: 1_760_000_000_000,
    exchanges: [start, login, authenticate, callback, home],
    inputs: input([
      { name: 'user', type: 'email', value: 'gina@example.com' },
      { name: 'pass', type: 'password', value: 'Gina-pass-123' },
      { name: 'code', autocomplete: 'one-time-code', value: '482913' },
    ]),
  };
}

export const all = {
  'form-login': formLogin, 'json-bearer': jsonBearer, 'oidc-totp': oidcTotp, 'sso-edge-cases': ssoEdgeCases,
};
