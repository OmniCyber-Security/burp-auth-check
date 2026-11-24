import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyse, buildRegex, tokenish, identifier, redact } from '../src/lib/analyse.js';
import { generateScript } from '../src/lib/groovy.js';
import { identityExport } from '../src/lib/identities.js';
import { formLogin, jsonBearer, oidcTotp, ssoEdgeCases } from './fixtures/scenarios.js';

const included = (analysis) => analysis.exchanges.filter((x) => x.included).map((x) => `${x.method} ${x.url}`);

test('a form login keeps the login page for its CSRF token and drops the noise', () => {
  const analysis = analyse(formLogin());
  assert.deepEqual(included(analysis), [
    'GET https://app.example.com/login',
    'POST https://app.example.com/login',
  ]);
  assert.equal(analysis.exchanges.find((x) => x.marker).url, 'https://app.example.com/dashboard');
});

test('credentials are recognised from what was typed, and unrelated fields are not', () => {
  const { params } = analyse(formLogin());
  assert.deepEqual(params.map((p) => [p.name, p.type, p.required]), [
    ['password', 'SECRET', true],
    ['username', 'STRING', true],
  ]);
});

test('the recorded credential literals never reach the script, not even its comments', () => {
  for (const make of [formLogin, jsonBearer, oidcTotp, ssoEdgeCases]) {
    const capture = make();
    const script = generateScript(analyse(capture).plan);
    for (const input of capture.inputs) {
      if (input.reason === 'submit') {
        assert.ok(!script.includes(input.value), `${capture.id}: ${input.name} value leaked into the script`);
      }
    }
  }
});

test('a JSON body sent as text/plain keeps its type, and a numeric code is generated', () => {
  const script = generateScript(analyse(ssoEdgeCases()).plan);
  assert.match(script, /http\.post\(u3, groovy\.json\.JsonOutput\.toJson\(\[.*'otp': \(otp as Long\)/);
  assert.match(script, /'text\/plain;charset=UTF-8'/);
});

test('names that are Groovy keywords are never used as variables', () => {
  const script = generateScript(analyse(ssoEdgeCases()).plan);
  assert.match(script, /def continueValue = /);
  assert.match(script, /def gotoValue = /);
  assert.ok(!/def (continue|goto) /.test(script));
});

test('the page title cannot end the header comment', () => {
  const script = generateScript(analyse(ssoEdgeCases()).plan);
  const header = script.slice(0, script.indexOf('*/') + 2);
  assert.match(header, /Sign in \*\\\/ System\.exit\(1\)/);
  assert.ok(!script.slice(header.length).includes('System.exit'), 'title text escaped the comment');
});

test('a short credential inside an unrelated value is left alone', () => {
  const capture = formLogin();
  capture.inputs[0].value = 'admin';
  capture.exchanges[3].requestBody = '_csrf=Tq9-csrf-7781xYz&username=admin&password=s3cret%21pw&next=%2Fadmin%2Fhome';
  const script = generateScript(analyse(capture).plan);
  assert.match(script, /'next': '\/admin\/home'/);
  assert.match(script, /'username': creds\.username/);
});

test('a distinctive credential inside a longer value is substituted', () => {
  const capture = formLogin();
  capture.exchanges[3].requestBody = '_csrf=Tq9-csrf-7781xYz&username=CORP%5Calice%40example.com&password=s3cret%21pw';
  const script = generateScript(analyse(capture).plan);
  assert.match(script, /'username': "CORP\\\\\$\{creds\.username\}"/);
});

test('credentials in a URL are replaced by their names wherever the URL is shown', () => {
  const params = [{ name: 'password', kind: 'credential', value: 'Pw0rd long' }];
  assert.equal(redact('https://a.test/auth?user=bob&pw=Pw0rd+long', params), 'https://a.test/auth?user=bob&pw=<password>');
});

test('a JSON login returns the bearer token pulled from the login response', () => {
  const analysis = analyse(jsonBearer());
  assert.deepEqual(included(analysis), ['POST https://api.example.com/api/auth/login']);
  const script = generateScript(analysis.plan);
  assert.match(script, /http\.json\(r1\)\?\.'data'\?\.'accessToken'/);
  assert.match(script, /'Authorization': "Bearer \$\{accessToken\}"/);
});

test('a static header that came from config, not the server session, stays literal', () => {
  // X-Client-Version first appears in a response, but is short and word-like
  // enough to be a constant, which is what it is.
  const script = generateScript(analyse(jsonBearer()).plan);
  assert.match(script, /'X-Client-Version': '2\.4\.1'/);
});

test('redirect hops follow the Location the server sends, not the recorded URL', () => {
  const script = generateScript(analyse(oidcTotp()).plan);
  assert.match(script, /def u2 = location\(u1, r1\)/);
  assert.match(script, /def u5 = location\(u4, r4\)/);
  assert.ok(!script.includes("'c0de-5f6e7d8c9b'"), 'the authorization code must not be replayed');
});

test('a form action carrying flow ids is extracted whole and HTML-unescaped', () => {
  const script = generateScript(analyse(oidcTotp()).plan);
  assert.match(script, /htmlUnescape\(http\.extractFrom\(r2, 'id="kc-form-login"\[\^>\]\*\?action="\(\[\^"\]\*\)"'\)\)/);
  assert.match(script, /def u3 = formAction\n/);
  const code = script.split('\n').filter((line) => !line.trim().startsWith('//'))
    .map((line) => line.replace(/'Step \d+ \([^']*\)'/g, '')).join('\n');
  assert.ok(!code.includes('Sc0de-1a2b3c'), 'the recorded session_code must not be replayed');
});

test('a one-time code becomes a generated TOTP and a declared secret', () => {
  const analysis = analyse(oidcTotp());
  const script = generateScript(analysis.plan);
  assert.ok(analysis.plan.totp);
  assert.match(script, /param 'totpSecret', type: SECRET, required: true/);
  assert.match(script, /def otp = totp\(creds\.totpSecret\)/);
  assert.ok(!script.includes('482913'));
});

test('a request the tester excludes falls back to the recorded value and says so', () => {
  const capture = formLogin();
  const loginPage = capture.exchanges[0].id;
  const analysis = analyse(capture, { include: { [loginPage]: false } });
  assert.ok(analysis.warnings.some((w) => /_csrf.*excluded/.test(w)), analysis.warnings.join('\n'));
  assert.match(generateScript(analysis.plan), /'_csrf': 'Tq9-csrf-7781xYz'/);
});

test('choosing a different marker changes the session returned', () => {
  const capture = jsonBearer();
  const analysis = analyse(capture, { markerId: capture.exchanges[0].id });
  assert.equal(analysis.plan.result.headers.length, 0);
  assert.ok(analysis.warnings.some((w) => /carries nothing the login produced/.test(w)));
  assert.match(generateScript(analysis.plan), /throw new IllegalStateException\('The recording produced no session/);
});

test('session cookies can be narrowed to the ones that matter', () => {
  const analysis = analyse(formLogin(), { cookies: { pre_session: false } });
  assert.deepEqual(analysis.plan.result.cookies.map((c) => c.name), ['SESSION']);
});

test('cookies the browser already had are seeded and warned about', () => {
  const analysis = analyse(formLogin());
  assert.ok(analysis.warnings.some((w) => /cookie _ga, which the browser already had/.test(w)));
  assert.match(generateScript(analysis.plan), /jar\[hostOf\(u1\)\]\.putIfAbsent\('_ga', 'GA1\.2\.111'\)/);
});

test('the identity export is what Burp imports, one identity per credential set', () => {
  const analysis = analyse(formLogin());
  const script = generateScript(analysis.plan);
  const file = identityExport(script, analysis.plan, [
    { name: 'User 1', credentials: { username: 'alice@example.com', password: 'a', base: '' } },
    { name: 'User 2', credentials: { username: 'bob@example.com', password: 'b', stray: 'x' } },
  ]);
  assert.equal(file.format, 1);
  assert.equal(file.identities.length, 2);
  assert.deepEqual(file.identities[0].credentials, { username: 'alice@example.com', password: 'a' });
  assert.deepEqual(file.identities[1].credentials, { username: 'bob@example.com', password: 'b' });
  assert.equal(file.identities[1].authScript, script);
  assert.equal(file.identities[0].sessionCheckUrl, 'https://app.example.com/dashboard');
});

test('a custom session header is added to the strip list so the baseline one is removed', () => {
  const capture = jsonBearer();
  capture.exchanges[3].requestHeaders.push(['X-Session', capture.exchanges[3].requestHeaders
    .find(([n]) => n === 'Authorization')[1].slice(7)]);
  const analysis = analyse(capture);
  const file = identityExport('', analysis.plan, [{ name: 'a', credentials: {} }]);
  assert.match(file.identities[0].stripHeaders, /X-Session/);
});

// -- regex building -----------------------------------------------------------

test('buildRegex anchors an attribute to its element name, either attribute order', () => {
  assert.equal(buildRegex('<input type="hidden" name="csrf" value="abc123def">', 'abc123def'),
    'name="csrf"[^>]*?value="([^"]*)"');
  assert.equal(buildRegex('<meta content="abc123def" name="csrf-token">', 'abc123def'),
    'content="([^"]*)"[^>]*?name="csrf-token"');
});

test('buildRegex never uses \\s, which Java and JavaScript read differently', () => {
  const body = '<p>Your code:\u00a0Ab12Cd34Ef56</p>';
  const pattern = buildRegex(body, 'Ab12Cd34Ef56');
  assert.ok(!pattern.includes('\\s'), pattern);
  assert.equal(new RegExp(pattern).exec(body)[1], 'Ab12Cd34Ef56');
});

test('buildRegex falls back to surrounding text, and its first match is the value', () => {
  const body = 'var a = {"other":"zzz"}; window.boot = {"csrfToken":"Xy12-abc_99"};';
  const pattern = buildRegex(body, 'Xy12-abc_99');
  assert.equal(new RegExp(pattern).exec(body)[1], 'Xy12-abc_99');
});

test('buildRegex refuses rather than returning a pattern that finds the wrong value', () => {
  // Identical context twice: the first match is the decoy, so no pattern on
  // that context can be right; it must widen until it is unique.
  const body = 'token=AAAA1111 ... token=BBBB2222';
  const pattern = buildRegex(body, 'BBBB2222');
  assert.equal(new RegExp(pattern).exec(body)[1], 'BBBB2222');
});

test('tokenish ignores words, flags and short values', () => {
  for (const v of ['true', 'login', 'Sign In', 'code', 'authorization_code', '12345']) assert.ok(!tokenish(v), v);
  for (const v of ['Tq9-csrf-7781xYz', 'eyJhbGciOi.x.y', '1234567']) assert.ok(tokenish(v), v);
});

test('identifier makes Groovy-safe camelCase names', () => {
  assert.equal(identifier('_csrf'), 'csrf');
  assert.equal(identifier('X-CSRF-Token'), 'xCsrfToken');
  assert.equal(identifier('session_code'), 'sessionCode');
  assert.equal(identifier('2fa'), 'v2fa');
});

// -- a capture made by the real extension in Chromium -------------------------

test('a real recording: CSRF extracted, leftover cookie not seeded, nothing to warn about', async () => {
  const { readFileSync } = await import('node:fs');
  const capture = JSON.parse(readFileSync(new URL('./fixtures/live-form-login.json', import.meta.url), 'utf8'));
  const analysis = analyse(capture);
  assert.deepEqual(included(analysis), ['GET http://localhost:8765/login', 'POST http://localhost:8765/login']);
  assert.deepEqual(analysis.warnings, []);
  const script = generateScript(analysis.plan);
  assert.match(script, /def csrfToken = need\(http\.extractFrom\(r1, 'name="csrf_token"\[\^>\]\*\?value="\(\[\^"\]\*\)"'\)/);
  assert.ok(!/putIfAbsent\('pre'/.test(script), 'the pre-recording cookie must not be seeded');
  assert.deepEqual(analysis.plan.result.cookies.map((c) => c.name), ['pre', 'SID']);
});
