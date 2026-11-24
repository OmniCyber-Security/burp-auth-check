// Renders an analysis plan as an Auth Check script.
//
// The output is meant to be read and edited by a tester, so it favours the
// shapes the bundled templates use -- http.get / postForm / postJson, a params
// block, a thrown exception with a reason on every failure path -- over
// anything clever. Every request is checked against the status it returned
// when recorded, so a login that drifts fails loudly at the step that changed
// instead of returning an empty session.

const sq = (text) => `'${String(text).replace(/\\/g, '\\\\').replace(/'/g, "\\'")
  .replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t')}'`;

const dqPart = (text) => String(text).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$')
  .replace(/\r/g, '\\r').replace(/\n/g, '\\n').replace(/\t/g, '\\t');

/** A Groovy expression for a plan expression. */
export function render(expr) {
  switch (expr.kind) {
    case 'lit': return sq(expr.value);
    case 'base': return 'base';
    case 'param': return `creds.${expr.name}`;
    case 'var': return expr.name;
    case 'totp': return 'otp';
    case 'urlenc': return `http.urlEncode(${render(expr.of)})`;
    case 'base64': return `${render(expr.of)}.bytes.encodeBase64().toString()`;
    case 'location': return `u${expr.step}`;
    case 'qs': return `qs(${renderMap(expr.pairs)})`;
    case 'concat': {
      // A GString: literal text escaped, everything else interpolated.
      return `"${expr.parts.map((part) => (part.kind === 'lit' ? dqPart(part.value) : `\${${render(part)}}`)).join('')}"`;
    }
    case 'map': return renderMap(expr.entries);
    case 'list': return expr.items.length ? `[${expr.items.map(render).join(', ')}]` : '[]';
    case 'json-literal': return expr.value === null ? 'null' : JSON.stringify(expr.value);
    case 'number': return `(${render(expr.of)} as Long)`;
    default: throw new Error(`unknown expression ${expr.kind}`);
  }
}

function renderMap(entries) {
  if (!entries.length) return '[:]';
  return `[${entries.map(([key, value]) => `${sq(key)}: ${render(value)}`).join(', ')}]`;
}

function renderMapBlock(entries, indent) {
  if (!entries.length) return '[:]';
  const pad = ' '.repeat(indent + 4);
  return `[\n${entries.map(([key, value]) => `${pad}${sq(key)}: ${render(value)}`).join(',\n')}\n${' '.repeat(indent)}]`;
}

/**
 * Text from the recording (page title, URLs) placed in a comment. The title is
 * whatever the target's <title> says, so it must not be able to end the
 * comment and become code that runs inside Burp.
 */
const comment = (text) => String(text).replace(/[\r\n\u2028\u2029]+/g, ' ').replace(/\*\//g, '*\\/');

const pathOf = (url) => {
  try {
    const parsed = new URL(url);
    const shown = parsed.pathname + (parsed.search.length > 60 ? `${parsed.search.slice(0, 57)}...` : parsed.search);
    return `${parsed.host}${shown}`;
  } catch {
    return url;
  }
};

function extractionCode(variable) {
  const r = `r${variable.step}`;
  const how = variable.how;
  switch (how.kind) {
    case 'cookie':
      return how.decode === 'url'
        ? `URLDecoder.decode(http.cookie(${r}, ${sq(how.name)}) ?: '', 'UTF-8')`
        : `http.cookie(${r}, ${sq(how.name)})`;
    case 'location': return `location(u${variable.step}, ${r})`;
    case 'location-param':
      return `queryParam(http.header(${r}, 'Location'), ${sq(how.name)}${how.fragment ? ', true' : ''})`;
    case 'header': return `http.header(${r}, ${sq(how.name)})`;
    case 'json': {
      const path = how.path.map((key) => (typeof key === 'number' ? `?.getAt(${key})` : `?.${sq(key)}`)).join('');
      return `http.json(${r})${path}?.toString()`;
    }
    case 'regex': {
      const found = `http.extractFrom(${r}, ${sq(how.pattern)})`;
      if (how.decode === 'html') return `htmlUnescape(${found})`;
      if (how.decode === 'url') return `URLDecoder.decode(${found} ?: '', 'UTF-8')`;
      if (how.decode === 'json') return `${found}?.replace('\\\\/', '/')`;
      return found;
    }
    default: throw new Error(`unknown extraction ${how.kind}`);
  }
}

function describe(variable) {
  const how = variable.how;
  const where = {
    cookie: `cookie ${how.name}`,
    location: 'the redirect Location',
    'location-param': `${how.name} in the redirect Location`,
    header: `response header ${how.name}`,
    json: `JSON field ${(how.path || []).join('.')}`,
    regex: 'the page body',
  }[how.kind];
  return `${variable.hint} (${where} of step ${variable.step})`;
}

function paramLine(param) {
  const options = [`type: ${param.type}`];
  if (param.required) options.push('required: true');
  if (param.default != null) options.push(`default: ${sq(param.default)}`);
  if (param.label && param.label !== param.name) options.push(`label: ${sq(param.label)}`);
  let line = `    param ${sq(param.name)}, ${options.join(', ')}`;
  if (param.help) line += `,\n          help: ${sq(param.help)}`;
  return line;
}

/**
 * @param plan    analysis.plan
 * @param options { generatedAt?: string }  fixed in tests so output is stable
 */
export function generateScript(plan, options = {}) {
  const lines = [];
  const add = (...more) => lines.push(...more);
  const origin = plan.baseOrigin || 'the target';
  const steps = plan.steps;
  const usesBase = JSON.stringify(steps).includes('"base"') || JSON.stringify(plan.result).includes('"base"');
  const allExtract = steps.flatMap((s) => s.extract);
  const needs = (kind, decode) => allExtract.some((v) => v.how.kind === kind && (!decode || v.how.decode === decode));
  const json = JSON.stringify(steps);
  const usesQs = json.includes('"kind":"qs"');
  const usesLocation = needs('location') || steps.some((s) => s.url.kind === 'location');
  const usesQueryParam = needs('location-param');
  const usesHtml = needs('regex', 'html');
  const usesUrlDecoder = needs('cookie', 'url') || needs('regex', 'url');
  const usesTotp = plan.totp;

  add('/*');
  add(` * Recorded login${comment(plan.title ? `: ${plan.title}` : ` for ${origin}`)}`);
  add(' *');
  add(` * Generated by the Auth Check Recorder from a capture of ${comment(origin)}${
    options.generatedAt ? ` on ${options.generatedAt}` : ''}.`);
  add(` * ${steps.length} request${steps.length === 1 ? '' : 's'}, replayed in the order the browser sent them.`);
  add(' * Values the server handed out -- CSRF tokens, flow ids, codes, cookies -- are');
  add(' * pulled from the response that issued them, and each request is checked');
  add(' * against the status it returned when recorded, so a login that changes');
  add(' * fails at the step that changed.');
  if (plan.sessionCheckUrl) {
    add(' *');
    add(' * Suggested "Session lifetime" settings:');
    add(` *   Session-check URL : ${comment(plan.sessionCheckUrl)}`);
  }
  add(' */');
  add('');
  if (usesTotp) {
    add('import javax.crypto.Mac', 'import javax.crypto.spec.SecretKeySpec', '');
  }

  const declared = [];
  if (usesBase) {
    declared.push({ name: 'base', type: 'URL', default: plan.baseOrigin, label: 'Base URL',
      help: 'Origin the login was recorded against. Change it to replay the same flow elsewhere' });
  }
  const referenced = new Set([...json.matchAll(/"kind":"param","name":"([^"]+)"/g)].map((m) => m[1]));
  for (const m of JSON.stringify(plan.result).matchAll(/"kind":"param","name":"([^"]+)"/g)) referenced.add(m[1]);
  for (const param of plan.params) {
    if (param.kind === 'totp' ? usesTotp : referenced.has(param.name)) {
      declared.push({ ...param, default: undefined });
    }
  }
  if (declared.length) {
    add('params {');
    add(declared.map(paramLine).join('\n'));
    add('}', '');
  }

  if (usesBase) {
    add("def base = creds.base.replaceAll('/+$', '')");
  }
  add('');
  add('// What the browser sent on every request.');
  add(`def browser = ${renderMapBlock(plan.browser.map((h) => [h.name, { kind: 'lit', value: h.value }]), 0)}`);
  add('');
  add('// The browser kept cookies for the flow; the http helper does not, so this does.');
  add('// Keyed by host, so an identity provider and the app can both set a JSESSIONID.');
  add('def jar = [:].withDefault { [:] }');
  add('');
  add("def hostOf = { String url -> (url =~ /^[A-Za-z][A-Za-z0-9+.-]*:\\/\\/(?:[^@\\/?#]*@)?([^:\\/?#]+)/).with { it.find() ? it.group(1).toLowerCase() : '' } }");
  add("def siteOf = { String host -> host.tokenize('.').takeRight(2).join('.') }");
  add('');
  add('// A cookie for this URL: one its own host set, else one set elsewhere on the same site.');
  add('def cookieValue = { String url, String name ->');
  add('    String host = hostOf(url)');
  add('    if (jar[host].containsKey(name)) {');
  add('        return jar[host][name]');
  add('    }');
  add('    jar.find { h, cookies -> cookies.containsKey(name) && siteOf(h) == siteOf(host) }?.value?.get(name)');
  add('}');
  add('');
  add('def cookieHeader = { String url, String... names ->');
  add("    names.findAll { cookieValue(url, it) != null }.collect { \"${it}=${cookieValue(url, it)}\" }.join('; ')");
  add('}');
  add('');
  add(`def headers = { Map extra = [:] -> (browser + extra).findAll { k, v -> v != null && v != '' } }`);
  add('');
  add('// Sends nothing itself: checks a response against the recording and keeps its cookies.');
  add('def step = { resp, String url, String label, int recorded ->');
  add('    int got = http.status(resp)');
  add('    if (got == 0) {');
  add('        throw new IllegalStateException("${label}: no response")');
  add('    }');
  add('    if (got.intdiv(100) != recorded.intdiv(100)) {');
  add('        throw new IllegalStateException("${label}: HTTP ${got}, but the recording got ${recorded}. " +');
  add('                "Body started: ${http.body(resp).take(300)}")');
  add('    }');
  add('    http.cookies(resp).each { name, value ->');
  add('        if (value) {');
  add('            jar[hostOf(url)][name] = value');
  add('        } else {');
  add('            jar[hostOf(url)].remove(name)');
  add('        }');
  add('    }');
  add('    resp');
  add('}');
  add('');
  add('def need = { value, String what ->');
  add("    if (value == null || value == '') {");
  add('        throw new IllegalStateException("Could not find ${what}. The login flow no longer matches the recording.")');
  add('    }');
  add('    value');
  add('}');
  if (steps.some((s) => s.method !== 'GET' && s.method !== 'POST')) {
    add('');
    add('def withHeaders = { request, Map extra ->');
    add('    extra.inject(request) { req, h -> req.withRemovedHeader(h.key).withAddedHeader(h.key, h.value as String) }');
    add('}');
  }
  if (usesQs) {
    add('');
    add("def qs = { Map q -> q.collect { k, v -> http.urlEncode(k as String) + '=' + http.urlEncode(v as String) }.join('&') }");
  }
  if (usesLocation) {
    add('');
    add('def location = { String from, resp ->');
    add("    String target = need(http.header(resp, 'Location'), \"a redirect from ${from}\")");
    add("    target = target.split('#')[0]");
    add("    if (target ==~ /(?i)https?:.*/) {");
    add('        return target');
    add('    }');
    add('    def uri = new URI(from)');
    add("    target.startsWith('/') ? \"${uri.scheme}://${uri.rawAuthority}${target}\" : uri.resolve(target).toString()");
    add('}');
  }
  if (usesQueryParam) {
    add('');
    add('def queryParam = { String url, String name, boolean fragment = false ->');
    add("    if (!url) {");
    add('        return null');
    add('    }');
    add("    String part = fragment ? url.substring(url.indexOf('#') + 1) : (url.contains('?') ? url.substring(url.indexOf('?') + 1) : '')");
    add("    part = part.split('#')[0]");
    add("    def pair = part.split('&').find { it.startsWith(name + '=') }");
    add("    pair == null ? null : URLDecoder.decode(pair.substring(name.length() + 1), 'UTF-8')");
    add('}');
  }
  if (usesHtml) {
    add('');
    add('def htmlUnescape = { String text ->');
    add('    text?.replaceAll(/&#x([0-9a-fA-F]+);/) { all, hex -> new String(Character.toChars(Integer.parseInt(hex, 16))) }');
    add('        ?.replaceAll(/&#([0-9]+);/) { all, dec -> new String(Character.toChars(Integer.parseInt(dec))) }');
    add("        ?.replace('&quot;', '\"')?.replace('&lt;', '<')?.replace('&gt;', '>')?.replace('&apos;', \"'\")?.replace('&amp;', '&')");
    add('}');
  }
  if (usesTotp) {
    add('');
    add(TOTP);
  }

  let otpDeclared = false;
  for (const step of steps) {
    add('');
    add(`// Step ${step.n}: ${comment(`${step.method} ${pathOf(step.displayUrl)}`)}  (recorded HTTP ${step.status})`);
    const url = step.url.kind === 'location' ? `location(u${step.url.step}, r${step.url.step})` : render(step.url);
    add(`def u${step.n} = ${url}`);
    const urlRef = `u${step.n}`;
    for (const cookie of step.cookies.filter((c) => !c.fromJar)) {
      add(`jar[hostOf(${urlRef})].putIfAbsent(${sq(cookie.name)}, ${sq(cookie.value)})  // ${cookie.reason === 'excluded'
        ? 'set by a request left out of this script' : 'already in the browser before recording'}`);
    }
    if (JSON.stringify(step).includes('"totp"')) {
      // Generated per step, right before it is sent, so it is never a step stale.
      add(`${otpDeclared ? '' : 'def '}otp = totp(creds.totpSecret)`);
      otpDeclared = true;
    }
    const label = sq(`Step ${step.n} (${step.method} ${pathOf(step.displayUrl)})`);
    const type = step.body.kind.startsWith('form') ? 'application/x-www-form-urlencoded'
      : step.body.contentType || (step.body.kind === 'json' ? 'application/json' : 'text/plain');
    let call;
    if (step.method === 'GET' && step.body.kind === 'none') {
      call = `http.get(${urlRef}, ${headerArg(step, urlRef)})`;
    } else if (step.method === 'POST' && step.body.kind === 'form') {
      call = `http.postForm(${urlRef}, ${renderMapBlock(step.body.pairs, 8)}, ${headerArg(step, urlRef)})`;
    } else if (step.method === 'POST' && step.body.kind === 'json' && /^application\/json\b/i.test(type)) {
      call = `http.postJson(${urlRef}, ${render(step.body.value)}, ${headerArg(step, urlRef)})`;
    } else if (step.method === 'POST') {
      call = `http.post(${urlRef}, ${bodyExpr(step.body)}, ${sq(type)}, ${headerArg(step, urlRef)})`;
    } else {
      const extra = step.body.kind === 'none' ? [] : [`'Content-Type': ${sq(type)}`];
      const request = `http.request(${urlRef}).withMethod(${sq(step.method)})${
        step.body.kind === 'none' ? '' : `.withBody(${bodyExpr(step.body)})`}`;
      call = `http.send(withHeaders(${request}, ${headerArg(step, urlRef, extra)}))`;
    }
    add(`def r${step.n} = step(${call}, ${urlRef}, ${label}, ${step.status})`);
    for (const variable of step.extract) {
      add(`def ${variable.name} = need(${extractionCode(variable)}, ${sq(describe(variable))})`);
    }
  }

  add('');
  const result = plan.result;
  if (!result.cookies.length && !result.headers.length) {
    add("throw new IllegalStateException('The recording produced no session to return. ' +");
    add("        'Pick a marker request on the Session tab of the recorder and generate again.')");
  } else {
    add(`log.info "Logged in as \${identity}${steps.length ? ` after ${steps.length} request${steps.length === 1 ? '' : 's'}` : ''}"`);
    add('');
    if (result.cookies.some((c) => c.fromJar)) {
      add('// The cookies the browser sent with the request that proved the session.');
      add(`def proof = ${render(result.proofUrl)}`);
      add('');
    }
    add('return [');
    const parts = [];
    if (result.cookies.length) {
      parts.push(`    cookies: [\n${result.cookies.map((c) => `        ${sq(c.name)}: ${c.fromJar
        ? `need(cookieValue(proof, ${sq(c.name)}), ${sq(`session cookie ${c.name}`)})` : sq(c.value)}`).join(',\n')}\n    ]`);
    }
    if (result.headers.length) {
      parts.push(`    headers: [\n${result.headers.map((h) => `        ${sq(h.name)}: ${render(h.value)}`).join(',\n')}\n    ]`);
    }
    add(parts.join(',\n'));
    add(']');
  }
  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;
}

function headerArg(step, urlRef, extra = []) {
  const entries = step.headers.map((h) => `${sq(h.name)}: ${render(h.value)}`);
  if (step.cookies.length) entries.push(`'Cookie': cookieHeader(${urlRef}, ${step.cookies.map((c) => sq(c.name)).join(', ')})`);
  entries.push(...extra);
  return entries.length ? `headers([${entries.join(', ')}])` : 'headers()';
}

function bodyExpr(body) {
  switch (body.kind) {
    case 'none': return "''";
    case 'form':
    case 'form-pairs': {
      return `[${body.pairs.map(([k, v]) => `[${sq(k)}, ${render(v)}]`).join(', ')}].collect { http.urlEncode(it[0]) + '=' + http.urlEncode(it[1] as String) }.join('&')`;
    }
    case 'json': return `groovy.json.JsonOutput.toJson(${render(body.value)})`;
    default: return render(body.value);
  }
}

const TOTP = `/** RFC 6238 TOTP, 6 digits, 30 second step, HMAC-SHA1. */
def totp = { String base32Secret ->
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
}`;
