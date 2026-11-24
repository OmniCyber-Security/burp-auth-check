// Works out, from a recorded login, what an auth script has to reproduce.
//
// Three questions, answered in order:
//
//   1. Which values in the requests are the tester's credentials?  Those become
//      `creds.*` parameters, so one script serves every identity.
//   2. Which values were handed out by the server and sent back later -- CSRF
//      tokens, flow ids, authorization codes, cookies?  Those become extractions
//      from the response that produced them.
//   3. Which requests does the session actually depend on?  Starting from the
//      request that proves the session (the "marker") and every request that
//      carried a credential, the producers of everything they send are pulled
//      in transitively. Analytics, asset fetches and page chrome fall away.
//
// The output is a plan: a list of steps whose every value is an expression
// (literal, credential, extracted variable, cookie), plus the session material
// to return. groovy.js turns the plan into source; nothing here knows Groovy.

import {
  header, headerValues, parseQuery, splitUrl, parseCookieHeader, parseSetCookie,
  cookieApplies, contentType, isFormBody, isJsonType, tryJson, jsonLeaves, encodings,
  decodeBase64, looksStatic, looksSecret, safeDecode,
} from './http.js';

/** Headers the script never replays: transport, caching, or set by the helper. */
const DROPPED = new Set([
  'host', 'content-length', 'connection', 'keep-alive', 'accept-encoding',
  'upgrade-insecure-requests', 'cache-control', 'pragma', 'priority', 'dnt', 'te',
  'if-none-match', 'if-modified-since', 'purpose', 'cookie', 'content-type', 'expect',
]);
/** Sent on every request, so they go in one shared map at the top of the script. */
const BROWSER = ['user-agent', 'accept-language'];

/** Names the generated script already uses, plus every Groovy keyword. */
const RESERVED = new Set([
  'base', 'jar', 'http', 'creds', 'log', 'vars', 'api', 'identity', 'browser', 'step',
  'need', 'headers', 'location', 'queryParam', 'cookieHeader', 'cookieValue', 'hostOf',
  'siteOf', 'remember', 'qs', 'totp', 'htmlUnescape', 'otp', 'session', 'material', 'proof',
  'withHeaders', 'it', 'owner', 'delegate', 'this', 'super',
  'abstract', 'as', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char', 'class',
  'const', 'continue', 'def', 'default', 'do', 'double', 'else', 'enum', 'extends', 'false',
  'final', 'finally', 'float', 'for', 'goto', 'if', 'implements', 'import', 'in', 'instanceof',
  'int', 'interface', 'long', 'native', 'new', 'non', 'null', 'package', 'permits', 'private',
  'protected', 'public', 'record', 'return', 'sealed', 'short', 'static', 'strictfp', 'switch',
  'synchronized', 'threadsafe', 'throw', 'throws', 'trait', 'transient', 'true', 'try', 'var',
  'void', 'volatile', 'while', 'yield',
]);

// -- preparing the capture ---------------------------------------------------

function prepare(capture) {
  const exchanges = (capture.exchanges || [])
    .filter((x) => x.status > 0 && !looksStatic(x.url) && /^https?:/.test(x.url))
    .map((x, index) => {
      let responseText = x.responseBody;
      if (responseText != null && x.responseBodyBase64) responseText = decodeBase64(responseText);
      const url = splitUrl(x.url.split('#')[0]);
      const reqType = contentType(x.requestHeaders);
      const body = x.requestBody;
      let bodyKind = 'none';
      let bodyValue = null;
      if (body != null && body !== '') {
        if (isFormBody(x.requestHeaders)) {
          bodyKind = 'form';
          bodyValue = parseQuery(body);
        } else {
          // fetch() sends a string body as text/plain, so a JSON login often
          // does not say it is JSON. Parse it whatever it claims to be.
          const json = tryJson(body);
          if (json !== undefined) {
            bodyKind = 'json';
            bodyValue = json;
          } else {
            bodyKind = 'raw';
            bodyValue = body;
          }
        }
      }
      const setCookies = headerValues(x.responseHeaders, 'set-cookie').map(parseSetCookie)
        .filter((cookie) => cookie.name);
      return {
        ...x,
        index,
        urlNoFragment: x.url.split('#')[0],
        parts: url,
        bodyKind,
        bodyValue,
        sentCookies: parseCookieHeader(header(x.requestHeaders, 'cookie')),
        setCookies,
        responseText: responseText ?? null,
        responseJson: tryJson(responseText),
        location: resolveLocation(x),
      };
    });
  return exchanges;
}

function resolveLocation(x) {
  const location = header(x.responseHeaders, 'location');
  if (!location) return null;
  try {
    return new URL(location, x.url).href.split('#')[0];
  } catch {
    return null;
  }
}

// -- credentials ---------------------------------------------------------------

const USERNAME = /user|email|login|account|ident|upn/i;
const OTP = /otp|totp|mfa|2fa|one.?time|verification|code|token|pin/i;

/** Classifies what the tester typed into named parameters for the script. */
export function detectParams(capture, exchanges) {
  const byValue = new Map();
  for (const input of capture.inputs || []) {
    const value = input.value;
    if (!value || byValue.has(value)) {
      if (byValue.has(value) && input.reason === 'submit') byValue.get(value).submitted = true;
      continue;
    }
    byValue.set(value, { ...input, submitted: input.reason === 'submit' });
  }

  const params = [];
  const used = new Set(['base']);
  const unique = (name) => {
    let candidate = name;
    for (let n = 2; used.has(candidate) || RESERVED.has(candidate); n++) candidate = `${name}${n}`;
    used.add(candidate);
    return candidate;
  };

  // Passwords first, so a username field holding the same text cannot claim it.
  const inputs = [...byValue.values()].sort((a, b) =>
    (b.type === 'password') - (a.type === 'password'));
  for (const input of inputs) {
    const field = input.name || input.id || input.label || input.placeholder || '';
    if (!sentAnywhere(input.value, exchanges)) continue;
    if (input.type === 'password') {
      params.push({ name: unique('password'), type: 'SECRET', required: true,
        value: input.value, field, label: 'Password', kind: 'credential' });
    } else if (/^\d{6,8}$/.test(input.value)
        && (input.autocomplete === 'one-time-code' || OTP.test(field) || input.inputmode === 'numeric')) {
      if (!params.some((p) => p.kind === 'totp')) {
        params.push({ name: unique('totpSecret'), type: 'SECRET', required: true,
          value: '', code: input.value, field, label: 'TOTP secret', kind: 'totp',
          help: 'Base32 secret from the enrolment QR code. Treat it as a password' });
      }
    } else if (input.autocomplete === 'username' || input.type === 'email'
        || USERNAME.test(field) || !params.some((p) => p.name === 'username')) {
      const isUser = !params.some((p) => p.name === 'username');
      const name = isUser ? unique('username') : unique(identifier(field) || 'value');
      params.push({ name, type: looksSecret(name) ? 'SECRET' : 'STRING', required: isUser,
        value: input.value, field, label: isUser ? 'Username' : (input.label || field || name),
        kind: 'credential' });
    } else {
      const name = unique(identifier(field) || 'value');
      params.push({ name, type: looksSecret(name) ? 'SECRET' : 'STRING', required: false,
        value: input.value, field, label: input.label || field || name, kind: 'credential' });
    }
  }
  return params;
}

function sentAnywhere(value, exchanges) {
  return exchanges.some((x) => requestContains(x, value));
}

function requestText(x) {
  const headers = x.requestHeaders.filter(([name]) => name.toLowerCase() !== 'referer')
    .map(([n, v]) => `${n}: ${v}`).join('\n');
  return `${safeDecode(x.urlNoFragment)}\n${headers}\n${x.requestBody || ''}\n${
    x.bodyKind === 'form' ? x.bodyValue.map(([, v]) => v).join('\n') : ''}`;
}

function requestContains(x, value) {
  if (!x._requestText) x._requestText = requestText(x);
  return x._requestText.includes(value) || basicContains(x, value);
}

function basicContains(x, value) {
  const auth = header(x.requestHeaders, 'authorization') || '';
  const match = /^basic\s+(.+)$/i.exec(auth);
  if (!match) return false;
  const decoded = decodeBase64(match[1].trim()) || '';
  return decoded.includes(value);
}

function responseContains(x, value) {
  if (!x._responseText) {
    x._responseText = `${x.responseHeaders.map(([n, v]) => `${n}: ${v}`).join('\n')}\n${
      x.location || ''}\n${safeDecode(x.location || '')}\n${x.responseText || ''}`;
  }
  return encodings(value).some((form) => x._responseText.includes(form.text));
}

/** Whether `part` occurs in `value` with no letter or digit glued to either side. */
function bounded(value, part) {
  let at = value.indexOf(part);
  while (at >= 0) {
    const before = value[at - 1];
    const after = value[at + part.length];
    if ((!before || !/[A-Za-z0-9]/.test(before)) && (!after || !/[A-Za-z0-9]/.test(after))) return true;
    at = value.indexOf(part, at + 1);
  }
  return false;
}

/** Short words and booleans are never treated as server-issued values. */
export function tokenish(value) {
  if (typeof value !== 'string' || value.length < 6) return false;
  if (/^[a-z]+([_. -][a-z]+)*$/i.test(value) && !/[a-z][A-Z]/.test(value) && value.length < 24) return false;
  if (/^(true|false|null|undefined)$/i.test(value)) return false;
  return true;
}

// -- finding where a value came from -----------------------------------------

/**
 * How the response of `x` can give back `value`, or null. Tried from most to
 * least robust: a cookie or header survives page redesigns, a regex may not.
 */
function extraction(x, value) {
  for (const cookie of x.setCookies) {
    if (cookie.value === value) return { kind: 'cookie', name: cookie.name };
    if (cookie.value && safeDecode(cookie.value) === value) {
      return { kind: 'cookie', name: cookie.name, decode: 'url' };
    }
  }
  if (x.location) {
    if (x.location === value) return { kind: 'location' };
    try {
      const params = new URL(x.location).searchParams;
      for (const [name, v] of params) if (v === value) return { kind: 'location-param', name };
      const fragment = new URL(header(x.responseHeaders, 'location'), x.url).hash.slice(1);
      for (const [name, v] of parseQuery(fragment)) {
        if (v === value) return { kind: 'location-param', name, fragment: true };
      }
    } catch { /* unparseable Location */ }
  }
  for (const [name, v] of x.responseHeaders) {
    const lower = name.toLowerCase();
    if (lower === 'set-cookie' || lower === 'location') continue;
    if (v === value) return { kind: 'header', name };
  }
  if (x.responseJson !== undefined) {
    const leaf = jsonLeaves(x.responseJson).find((l) => l.value === value);
    if (leaf) return { kind: 'json', path: leaf.path };
  }
  if (x.responseText) {
    for (const form of encodings(value)) {
      const pattern = buildRegex(x.responseText, form.text);
      if (pattern) return { kind: 'regex', pattern, decode: form.decode };
    }
  }
  return null;
}

const escapeRegex = (text) => text.replace(/[\\^$.|?*+()[\]{}]/g, '\\$&');

/** Literal context as a pattern, with whitespace runs loosened to \s+. */
function contextPattern(text) {
  // Spelled out rather than \s: JavaScript's \s also matches no-break and
  // other Unicode spaces, Java's does not, and the pattern runs in Java.
  return text.split(/[ \t\n\r\f]+/).map(escapeRegex).join('[ \\t\\n\\r\\f]+');
}

function valueClass(value, next) {
  if (next === '"') return '[^"]';
  if (next === "'") return "[^']";
  if (/^[A-Za-z0-9_-]+$/.test(value)) return '[A-Za-z0-9_-]';
  if (/^[A-Za-z0-9+/=_-]+$/.test(value)) return '[A-Za-z0-9+/=_-]';
  if (next === '<') return '[^<]';
  return '[^"\'<>& \\t\\n\\r\\f]';
}

/**
 * A regex whose first match's first group is exactly `text`, built from what
 * surrounds its first occurrence. Uses only syntax Java and JavaScript read
 * the same way, because it is verified here and run by java.util.regex.
 */
export function buildRegex(body, text) {
  const at = body.indexOf(text);
  if (at < 0) return null;
  const next = body[at + text.length] || '';
  const cls = valueClass(text, next);
  const verify = (pattern) => {
    try {
      const match = new RegExp(pattern).exec(body);
      return match && match[1] === text ? pattern : null;
    } catch {
      return null;
    }
  };

  // An HTML attribute is best anchored to the element's name or id, which
  // survives the markup around it changing.
  const quote = body[at - 1];
  if (quote === '"' || quote === "'") {
    const tagStart = body.lastIndexOf('<', at);
    const tagEnd = body.indexOf('>', at);
    const attr = /([\w:-]+)=$/.exec(body.slice(Math.max(0, at - 40), at - 1));
    if (tagStart >= 0 && tagEnd > at && attr && at - tagStart < 2000) {
      const tag = body.slice(tagStart, tagEnd);
      const valueAt = at - tagStart;
      const anchor = /\s(name|id|property)=(["'])([^"']+)\2/g;
      let m;
      while ((m = anchor.exec(tag))) {
        const named = `${m[1]}=${m[2]}${escapeRegex(m[3])}${m[2]}`;
        const target = `${attr[1]}=${quote}(${quote === '"' ? '[^"]' : "[^']"}*)${quote}`;
        const pattern = m.index < valueAt
          ? `${named}[^>]*?${target}`
          : `${target}[^>]*?${named}`;
        const verified = verify(pattern);
        if (verified) return verified;
      }
    }
  }

  for (const width of [8, 12, 16, 24, 32, 48, 64, 96, 128]) {
    const left = body.slice(Math.max(0, at - width), at);
    if (!left) break;
    const verified = verify(`${contextPattern(left)}(${cls}+)`);
    if (verified) return verified;
    if (at - width <= 0) break;
  }
  return null;
}

// -- slots: every place a request carries a value ----------------------------

/** Returns the request's values, each tagged with where it sits. */
function slots(x) {
  const out = [];
  x.parts.path.split('/').forEach((segment, index) => {
    const value = safeDecode(segment);
    if (tokenish(value)) out.push({ where: 'path', index, name: 'pathSegment', value });
  });
  parseQuery(x.parts.query).forEach(([name, value], index) =>
    out.push({ where: 'query', index, name, value }));
  if (x.bodyKind === 'form') {
    x.bodyValue.forEach(([name, value], index) => out.push({ where: 'form', index, name, value }));
  } else if (x.bodyKind === 'json') {
    for (const leaf of jsonLeaves(x.bodyValue)) {
      const numeric = typeof leafAt(x.bodyValue, leaf.path) === 'number';
      out.push({ where: 'json', path: leaf.path, name: String(leaf.path.at(-1) ?? 'value'), value: leaf.value, numeric });
    }
  } else if (x.bodyKind === 'raw') {
    // No structure to walk, so every token-like run is a candidate.
    const seen = new Set();
    for (const token of x.bodyValue.split(/[^A-Za-z0-9_\-.~+/=%]+/)) {
      if (tokenish(token) && !seen.has(token)) {
        seen.add(token);
        out.push({ where: 'raw', name: 'value', value: token });
      }
    }
  }
  for (const [name, value] of x.requestHeaders) {
    const lower = name.toLowerCase();
    if (DROPPED.has(lower) || lower.startsWith('sec-') || lower.startsWith(':')
        || BROWSER.includes(lower) || lower === 'referer' || lower === 'origin' || lower === 'accept') continue;
    const scheme = /^(bearer|token|jwt|dpop|mac)\s+(.+)$/i.exec(value);
    out.push(scheme
      ? { where: 'header', name, value: scheme[2], prefix: `${scheme[1]} ` }
      : { where: 'header', name, value });
  }
  return out;
}

function leafAt(value, path) {
  return path.reduce((node, key) => (node == null ? node : node[key]), value);
}

// -- the analysis --------------------------------------------------------------

/**
 * @param capture  what the recorder saved
 * @param options  the tester's overrides from the editor:
 *   include      { [exchangeId]: true|false }  force a request in or out
 *   markerId     exchange that proves the session
 *   params       replaces the detected credential list
 *   baseOrigin   origin that becomes creds.base
 *   cookies      { [name]: true|false } session cookies to return
 *   headers      { [name]: true|false } session headers to return
 */
export function analyse(capture, options = {}) {
  const exchanges = prepare(capture);
  const params = options.params || detectParams(capture, exchanges);
  const warnings = [];

  const producers = new Map();
  /** Every earlier exchange whose response hands back `value`, newest first. */
  const producersOf = (value, before) => {
    const key = `${before}\u0000${value}`;
    if (producers.has(key)) return producers.get(key);
    let found = [];
    if (tokenish(value)) {
      const firstRequest = exchanges.findIndex((x) => x.index < before && requestContains(x, value));
      const firstResponse = exchanges.findIndex((x) => x.index < before && responseContains(x, value));
      // A value the client sent before the server ever said it is the client's
      // own (a redirect_uri, a client_id): it stays literal.
      const clientOwned = firstRequest >= 0 && (firstResponse < 0 || firstRequest <= firstResponse);
      if (!clientOwned && firstResponse >= 0) {
        for (let j = before - 1; j >= 0; j--) {
          const how = responseContains(exchanges[j], value) ? extraction(exchanges[j], value) : null;
          if (how) found.push({ index: j, how });
        }
      }
    }
    producers.set(key, found);
    return found;
  };

  const credentialFor = (value) => params.find((p) => p.kind === 'credential' && p.value === value);
  const distinctive = params.filter((p) => p.kind === 'credential' && p.value.length >= 6);
  const totp = params.find((p) => p.kind === 'totp');

  /** What a slot's value is, ignoring which steps end up included. */
  const classify = (x, slot) => {
    const credential = credentialFor(slot.value);
    if (credential) return { kind: 'param', name: credential.name };
    if (totp && slot.value === totp.code) return { kind: 'totp' };
    const found = producersOf(slot.value, x.index);
    if (found.length) return { kind: 'dynamic', producers: found };
    // A credential inside a longer value ("DOMAIN\\alice", a JSON string in a
    // raw body). Short credentials are left alone: "admin" inside "/admin/home"
    // is a path, not the username.
    const partial = distinctive.filter((p) => bounded(slot.value, p.value));
    if (partial.length) return { kind: 'contains', params: partial };
    return { kind: 'literal' };
  };

  // Per exchange: its slots, cookie setters, and redirect predecessor.
  for (const x of exchanges) {
    const found = slots(x);
    if (x.bodyKind === 'raw') {
      for (const p of params) {
        const value = p.kind === 'totp' ? p.code : p.value;
        if (value && value.length >= 3 && x.bodyValue.includes(value) && !found.some((s) => s.where === 'raw' && s.value === value)) {
          found.push({ where: 'raw', name: p.name, value });
        }
      }
    }
    x.slots = found.map((slot) => ({ ...slot, source: classify(x, slot) }));
    x.cookieSources = x.sentCookies.map(([name, value]) => {
      const setters = [];
      for (let j = x.index - 1; j >= 0; j--) {
        const set = exchanges[j].setCookies.find((c) => c.name === name);
        if (set && cookieApplies(set, exchanges[j].parts.host, x.parts.host)) setters.push(j);
      }
      return { name, value, setters };
    });
    const previous = x.redirectedFrom && exchanges.find((y) => y.id === x.redirectedFrom);
    x.redirectFrom = previous && previous.location === x.urlNoFragment ? previous.index : null;
    x.urlSource = null;
    if (x.redirectFrom == null && x.slots.some((s) => (s.where === 'query' || s.where === 'path')
        && s.source.kind === 'dynamic')) {
      const found = producersOf(x.urlNoFragment, x.index);
      if (found.length) x.urlSource = { kind: 'dynamic', producers: found };
    }
    x.credentialBearing = x.slots.some((s) => ['param', 'totp', 'contains'].includes(s.source.kind))
      || (header(x.requestHeaders, 'authorization') || '').match(/^basic\s/i) && params.some((p) =>
        p.kind === 'credential' && basicContains(x, p.value));
  }

  // -- the marker: the request that shows the login worked -------------------
  const lastCredential = exchanges.reduce((last, x) => (x.credentialBearing ? x.index : last), -1);
  const carriesFlowMaterial = (x) => x.cookieSources.some((c) => c.setters.length)
    || x.slots.some((s) => s.where === 'header' && s.source.kind === 'dynamic');
  let marker = options.markerId ? exchanges.find((x) => x.id === options.markerId) : null;
  if (!marker) {
    marker = exchanges.find((x) => x.index > lastCredential && x.status >= 200 && x.status < 300
      && carriesFlowMaterial(x))
      || exchanges.find((x) => x.index > lastCredential && x.status >= 200 && x.status < 300)
      || null;
  }
  if (lastCredential < 0) {
    warnings.push('No request carried a recorded credential. Was the login typed into the page while recording? '
      + 'If the browser autofilled it without a submit, add the values on the Credentials tab.');
  }

  // -- which steps the session depends on ------------------------------------
  const material = marker ? sessionMaterial(marker, options) : { cookies: [], headers: [] };

  const required = new Set();
  const visit = (index) => {
    if (required.has(index)) return;
    required.add(index);
    for (const dep of dependencies(exchanges[index], () => true)) visit(dep);
  };
  for (const x of exchanges) if (x.credentialBearing && (!marker || x.index < marker.index)) visit(x.index);
  if (marker) for (const dep of materialDependencies(marker, material, () => true)) visit(dep);

  const included = new Set();
  for (const x of exchanges) {
    const forced = options.include?.[x.id];
    if (forced === true || (forced !== false && required.has(x.index))) included.add(x.index);
  }
  const isIncluded = (index) => included.has(index);

  // -- the plan ----------------------------------------------------------------
  const variables = new Map();
  const names = new Set([...params.map((p) => p.name)]);
  const variableFor = (producer, how, hint) => {
    const key = `${producer}|${JSON.stringify(how)}`;
    if (!variables.has(key)) {
      variables.set(key, { name: freshName(identifier(hint) || 'value', names), producer, how, hint });
    }
    return variables.get(key);
  };
  const used = new Set();
  const notes = { generated: new Set(), missing: [] };

  /** The expression for a value as the plan stands (included steps only). */
  const expression = (x, slot) => {
    const source = slot.source;
    const wrap = (expr) => (slot.prefix ? concat([lit(slot.prefix), expr]) : expr);
    switch (source.kind) {
      case 'param':
        return wrap({ kind: 'param', name: source.name });
      case 'totp':
        return wrap({ kind: 'totp' });
      case 'contains':
        return wrap(substitute(slot.value, source.params));
      case 'dynamic': {
        const producer = source.producers.find((p) => isIncluded(p.index));
        if (!producer) {
          notes.missing.push({ step: x, slot, from: source.producers[0].index });
          return wrap(lit(slot.value));
        }
        const variable = variableFor(producer.index, producer.how, hintFor(producer.how, slot));
        used.add(variable);
        return wrap({ kind: 'var', name: variable.name });
      }
      default:
        if (slot.value.length >= 16 && /[0-9]/.test(slot.value) && /[a-z]/i.test(slot.value)
            && !exchanges.some((y) => y.index < x.index && requestContains(y, slot.value))) {
          notes.generated.add(slot.name);
        }
        return wrap(lit(slot.value));
    }
  };

  const ordered = exchanges.filter((x) => included.has(x.index));
  const baseOrigin = options.baseOrigin || ordered[0]?.parts.origin
    || (capture.tabUrl && safeOrigin(capture.tabUrl)) || null;
  const steps = [];
  const stepOf = new Map();
  for (const x of ordered) {
    const n = steps.length + 1;
    stepOf.set(x.index, n);
    const bySlot = (where, key) => x.slots.find((s) => s.where === where
      && (s.index === key || (where === 'json' && JSON.stringify(s.path) === JSON.stringify(key))
        || (where === 'header' && s.name === key)));

    // URL
    let url;
    if (x.redirectFrom != null && isIncluded(x.redirectFrom)) {
      url = { kind: 'location', step: () => stepOf.get(x.redirectFrom) };
    } else if (x.urlSource && x.urlSource.producers.some((p) => isIncluded(p.index))) {
      url = expression(x, { name: 'nextUrl', value: x.urlNoFragment, source: x.urlSource });
    } else {
      const pathParts = x.parts.path.split('/').map((segment, index) => {
        const slot = bySlot('path', index);
        return slot && slot.source.kind !== 'literal' ? { kind: 'urlenc', of: expression(x, slot) } : lit(segment);
      });
      const path = joinParts(pathParts, '/');
      const query = parseQuery(x.parts.query);
      const dynamicQuery = query.some((_, index) => bySlot('query', index).source.kind !== 'literal');
      const parts = [originExpr(x.parts.origin, baseOrigin), path];
      if (x.parts.query) {
        parts.push(lit('?'));
        parts.push(dynamicQuery
          ? { kind: 'qs', pairs: query.map(([name], index) => [name, expression(x, bySlot('query', index))]) }
          : lit(x.parts.query));
      }
      url = concat(parts);
    }

    // Headers
    const headerList = [];
    for (const [name, value] of x.requestHeaders) {
      const lower = name.toLowerCase();
      if (DROPPED.has(lower) || lower.startsWith('sec-') || lower.startsWith(':') || BROWSER.includes(lower)) continue;
      if (headerList.some((h) => h.name.toLowerCase() === lower)) continue;
      if (lower === 'origin' || lower === 'referer') {
        headerList.push({ name, value: originPrefixed(redact(value, params), baseOrigin) });
      } else if (lower === 'accept') {
        if (value !== '*/*') headerList.push({ name, value: lit(value) });
      } else if (lower === 'authorization' && /^basic\s/i.test(value) && x.credentialBearing) {
        headerList.push({ name, value: basicExpr(value, params) });
      } else {
        const slot = bySlot('header', name);
        headerList.push({ name, value: slot ? expression(x, slot) : lit(value) });
      }
    }

    // Cookies
    const cookies = x.cookieSources.map((c) => {
      const setter = c.setters.find(isIncluded);
      if (setter != null) return { name: c.name, fromJar: true };
      if (!c.setters.length && setLater(c.name, x.index)) return null;
      return { name: c.name, fromJar: false, value: c.value, reason: c.setters.length ? 'excluded' : 'preexisting' };
    }).filter(Boolean);

    // Body
    let body = { kind: x.bodyKind };
    if (x.bodyKind === 'form') {
      const duplicate = new Set(x.bodyValue.map(([k]) => k)).size !== x.bodyValue.length;
      body = { kind: duplicate ? 'form-pairs' : 'form',
        pairs: x.bodyValue.map(([name], index) => [name, expression(x, bySlot('form', index))]) };
    } else if (x.bodyKind === 'json') {
      body = { kind: 'json', value: jsonExpr(x.bodyValue, [], (path) => {
        const slot = bySlot('json', path);
        return slot ? expression(x, slot) : null;
      }), contentType: header(x.requestHeaders, 'content-type') || 'application/json' };
    } else if (x.bodyKind === 'raw') {
      body = { kind: 'raw', value: rawBody(x, x.bodyValue, expression), contentType: header(x.requestHeaders, 'content-type') || 'text/plain' };
    }

    steps.push({ n, id: x.id, method: x.method, url, displayUrl: redact(x.urlNoFragment, params), headers: headerList,
      cookies, body, status: x.status, extract: [], defineUrl: false });
  }

  // Session material, as expressions over the included steps.
  const result = { cookies: [], headers: [], proofUrl: null };
  if (marker) {
    result.proofUrl = concat([originExpr(marker.parts.origin, baseOrigin), lit(marker.parts.path)]);
    for (const cookie of material.cookies) {
      const source = marker.cookieSources.find((c) => c.name === cookie.name);
      const setter = source?.setters.find(isIncluded);
      if (setter != null) result.cookies.push({ name: cookie.name, fromJar: true });
      else if (source) result.cookies.push({ name: cookie.name, fromJar: false, value: source.value });
    }
    for (const h of material.headers) {
      const slot = marker.slots.find((s) => s.where === 'header' && s.name === h.name);
      result.headers.push({ name: h.name, value: slot ? expression(marker, slot) : lit(h.value) });
    }
    if (!result.cookies.length && !result.headers.length) {
      warnings.push('The marker request carries nothing the login produced, so there is no session to return. '
        + 'Pick a request made after logging in, or tick a cookie or header on the Session tab.');
    }
    for (const c of result.cookies.filter((c) => !c.fromJar)) {
      warnings.push(`Session cookie ${c.name} was not set by any included request, so its recorded value is `
        + 'returned as-is and will stop working when it expires. Record from a clean browser profile.');
    }
  } else {
    warnings.push('No request after the login looks authenticated. Keep browsing for a moment after signing in, '
      + 'then stop recording — or pick the marker request yourself.');
  }

  // Attach extractions to the step that produces them, in first-use order.
  for (const variable of used) {
    const step = steps.find((s) => s.n === stepOf.get(variable.producer));
    step.extract.push(variable);
    if (variable.how.kind === 'location') step.defineUrl = true;
  }
  for (const step of steps) {
    if (step.url.kind === 'location') {
      const from = steps.find((s) => s.n === step.url.step());
      if (from) from.defineUrl = true;
      step.url = { kind: 'location', step: step.url.step() };
    }
  }
  for (const variable of used) {
    if (variable.how.kind === 'location') variable.urlOf = stepOf.get(variable.producer);
    variable.step = stepOf.get(variable.producer);
  }

  const seeded = new Map();
  for (const step of steps) {
    for (const cookie of step.cookies.filter((c) => !c.fromJar)) {
      if (!seeded.has(cookie.name)) seeded.set(cookie.name, { ...cookie, steps: [] });
      seeded.get(cookie.name).steps.push(step.n);
    }
  }
  for (const cookie of seeded.values()) {
    const where = `Step${cookie.steps.length > 1 ? 's' : ''} ${cookie.steps.join(', ')}`;
    warnings.push(cookie.reason === 'excluded'
      ? `${where} send${cookie.steps.length > 1 ? '' : 's'} cookie ${cookie.name}, set by a request you excluded; the recorded value is used.`
      : `${where} send${cookie.steps.length > 1 ? '' : 's'} cookie ${cookie.name}, which the browser already had before recording. `
        + 'The script seeds it with the recorded value. Record in a fresh profile if the login depends on it.');
  }
  for (const miss of notes.missing) {
    warnings.push(`Step ${stepOf.get(miss.step.index) ?? '(session)'} sends ${miss.slot.name}, which came from `
      + `request #${miss.from + 1}. That request is excluded, so the recorded value is replayed and will likely be rejected.`);
  }
  if (notes.generated.size) {
    warnings.push(`Replayed as recorded, because the page's own JavaScript generated them: ${[...notes.generated].join(', ')}. `
      + 'Servers usually accept a replayed state, nonce or PKCE pair; if one does not, edit the script.');
  }

  const browser = [];
  const first = ordered[0];
  if (first) {
    for (const name of BROWSER) {
      const value = header(first.requestHeaders, name);
      if (value) browser.push({ name: canonical(first.requestHeaders, name), value });
    }
  }

  return {
    exchanges: exchanges.map((x) => summarise(x, included, required, marker, stepOf, params)),
    params,
    marker: marker ? marker.id : null,
    material,
    plan: {
      baseOrigin,
      browser,
      steps,
      result,
      totp: Boolean(totp) && steps.some((s) => JSON.stringify(s).includes('"totp"')),
      params,
      sessionCheckUrl: marker && marker.method === 'GET' ? marker.urlNoFragment : '',
      title: capture.title || '',
      recordedAt: capture.startedAt || null,
    },
    warnings: [...new Set(warnings)],
  };

  // -- local helpers that need the exchange list -------------------------------

  /**
   * A cookie the browser already had that the flow itself sets again later is
   * a leftover from loading the page before recording started. A fresh client
   * would not have it yet, so it is not sent rather than seeded stale.
   */
  function setLater(name, after) {
    return exchanges.some((y) => y.index >= after && included.has(y.index)
      && y.setCookies.some((c) => c.name === name));
  }

  function dependencies(x, allowed) {
    const deps = new Set();
    for (const slot of x.slots) {
      if (slot.source.kind === 'dynamic') {
        const p = slot.source.producers.find((q) => allowed(q.index));
        if (p) deps.add(p.index);
      }
    }
    for (const cookie of x.cookieSources) {
      const setter = cookie.setters.find(allowed);
      if (setter != null) deps.add(setter);
    }
    if (x.redirectFrom != null) deps.add(x.redirectFrom);
    else if (x.urlSource) {
      const p = x.urlSource.producers.find((q) => allowed(q.index));
      if (p) deps.add(p.index);
    }
    return deps;
  }

  function materialDependencies(x, chosen, allowed) {
    const deps = new Set();
    for (const cookie of chosen.cookies) {
      const setter = x.cookieSources.find((c) => c.name === cookie.name)?.setters.find(allowed);
      if (setter != null) deps.add(setter);
    }
    for (const h of chosen.headers) {
      const slot = x.slots.find((s) => s.where === 'header' && s.name === h.name);
      if (slot?.source.kind === 'dynamic') {
        const p = slot.source.producers.find((q) => allowed(q.index));
        if (p) deps.add(p.index);
      }
    }
    return deps;
  }

  function sessionMaterial(x, opts) {
    const cookies = [];
    for (const c of x.cookieSources) {
      const auto = c.setters.length > 0;
      const forced = opts.cookies?.[c.name];
      cookies.push({ name: c.name, auto, selected: forced ?? auto });
    }
    const headers = [];
    for (const slot of x.slots.filter((s) => s.where === 'header')) {
      const auto = slot.source.kind !== 'literal';
      const forced = opts.headers?.[slot.name];
      headers.push({ name: slot.name, value: (slot.prefix || '') + slot.value, auto, selected: forced ?? auto });
    }
    return {
      all: { cookies, headers },
      cookies: cookies.filter((c) => c.selected),
      headers: headers.filter((h) => h.selected),
    };
  }
}

/** What to call a variable: what the server called the value, else where it is sent. */
function hintFor(how, slot) {
  if (how.kind === 'json') {
    const key = [...how.path].reverse().find((k) => typeof k === 'string');
    if (key) return key;
  }
  if (how.kind === 'location-param' || how.kind === 'cookie' || how.kind === 'header') return how.name;
  if (how.kind === 'regex' && slot.name === 'nextUrl' && /action=/.test(how.pattern)) return 'formAction';
  if (how.kind === 'location') return 'redirectUrl';
  return slot.name;
}

// -- expression helpers --------------------------------------------------------

export const lit = (value) => ({ kind: 'lit', value });

export function concat(parts) {
  const flat = [];
  for (const part of parts) {
    if (!part) continue;
    if (part.kind === 'concat') flat.push(...part.parts);
    else flat.push(part);
  }
  const merged = [];
  for (const part of flat) {
    const last = merged[merged.length - 1];
    if (part.kind === 'lit' && last?.kind === 'lit') merged[merged.length - 1] = lit(last.value + part.value);
    else if (!(part.kind === 'lit' && part.value === '')) merged.push(part);
  }
  if (merged.length === 0) return lit('');
  return merged.length === 1 ? merged[0] : { kind: 'concat', parts: merged };
}

function joinParts(parts, separator) {
  const out = [];
  parts.forEach((part, index) => {
    if (index) out.push(lit(separator));
    out.push(part);
  });
  return concat(out);
}

function originExpr(origin, baseOrigin) {
  return origin === baseOrigin ? { kind: 'base' } : lit(origin);
}

function originPrefixed(value, baseOrigin) {
  if (baseOrigin && value.startsWith(baseOrigin)) return concat([{ kind: 'base' }, lit(value.slice(baseOrigin.length))]);
  return lit(value);
}

/** A URL fit for a comment: every recorded credential replaced by its name. */
export function redact(url, params) {
  let out = url;
  for (const p of params) {
    const value = p.kind === 'totp' ? p.code : p.value;
    if (!value || value.length < 3) continue;
    for (const form of new Set([value, encodeURIComponent(value), encodeURIComponent(value).replace(/%20/g, '+')])) {
      out = out.split(form).join(`<${p.name}>`);
    }
  }
  return out;
}

function substitute(value, params) {
  const sorted = [...params].sort((a, b) => b.value.length - a.value.length);
  let parts = [lit(value)];
  for (const param of sorted) {
    parts = parts.flatMap((part) => {
      if (part.kind !== 'lit' || !part.value.includes(param.value)) return [part];
      const pieces = part.value.split(param.value);
      const out = [];
      pieces.forEach((piece, i) => {
        if (i) out.push({ kind: 'param', name: param.name });
        out.push(lit(piece));
      });
      return out;
    });
  }
  return concat(parts);
}

function basicExpr(value, params) {
  const decoded = decodeBase64(value.replace(/^basic\s+/i, '').trim()) || '';
  return concat([lit('Basic '), { kind: 'base64', of: substitute(decoded, params.filter((p) => p.kind === 'credential' && p.value)) }]);
}

function rawBody(x, text, expression) {
  // Raw bodies have no structure to walk, so substitute known values in place.
  const replacements = [];
  for (const slot of x.slots) {
    if (slot.where !== 'header' && slot.source.kind !== 'literal') replacements.push(slot);
  }
  if (!replacements.length) return lit(text);
  let parts = [lit(text)];
  for (const slot of replacements) {
    parts = parts.flatMap((part) => {
      if (part.kind !== 'lit' || !part.value.includes(slot.value)) return [part];
      const out = [];
      part.value.split(slot.value).forEach((piece, i) => {
        if (i) out.push(expression(x, slot));
        out.push(lit(piece));
      });
      return out;
    });
  }
  return concat(parts);
}

function jsonExpr(value, path, lookup) {
  if (Array.isArray(value)) return { kind: 'list', items: value.map((v, i) => jsonExpr(v, [...path, i], lookup)) };
  if (value && typeof value === 'object') {
    return { kind: 'map', entries: Object.entries(value).map(([k, v]) => [k, jsonExpr(v, [...path, k], lookup)]) };
  }
  if (typeof value === 'string') return lookup(path) || lit(value);
  if (typeof value === 'number') {
    const expr = lookup(path);
    if (expr && expr.kind !== 'lit') return { kind: 'number', of: expr };
  }
  return { kind: 'json-literal', value };
}

function canonical(headers, name) {
  const found = headers.find(([n]) => n.toLowerCase() === name);
  const raw = found ? found[0] : name;
  return raw.toLowerCase() === raw ? raw.replace(/(^|-)([a-z])/g, (_, d, c) => d + c.toUpperCase()) : raw;
}

function safeOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** A Groovy-safe camelCase identifier from a field or parameter name. */
export function identifier(text) {
  const words = String(text || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (!words.length) return '';
  const name = words.map((w, i) => (i ? w[0].toUpperCase() + w.slice(1).toLowerCase() : w.toLowerCase())).join('');
  return /^[0-9]/.test(name) ? `v${name}` : name;
}

function freshName(base, names) {
  let name = RESERVED.has(base) ? `${base}Value` : base;
  if (/^r[0-9]+$|^u[0-9]+$/.test(name)) name = `${name}Value`;
  let candidate = name;
  for (let n = 2; names.has(candidate); n++) candidate = `${name}${n}`;
  names.add(candidate);
  return candidate;
}

function summarise(x, included, required, marker, stepOf, params) {
  const reasons = [];
  if (x.credentialBearing) reasons.push('sends credentials');
  const setNames = x.setCookies.filter((c) => !c.expired && c.value).map((c) => c.name);
  return {
    id: x.id,
    index: x.index,
    method: x.method,
    url: x.urlNoFragment,
    host: x.parts.host,
    path: x.parts.path + (x.parts.query ? `?${x.parts.query}` : ''),
    status: x.status,
    resourceType: x.resourceType,
    included: included.has(x.index),
    required: required.has(x.index),
    marker: marker ? marker.id === x.id : false,
    step: stepOf.get(x.index) ?? null,
    credentialBearing: Boolean(x.credentialBearing),
    setsCookies: setNames,
    dynamic: x.slots.filter((s) => s.source.kind === 'dynamic').map((s) => ({
      name: s.name, from: s.source.producers[0].index,
    })),
    usesParams: [...new Set(x.slots.filter((s) => s.source.kind === 'param').map((s) => s.source.name))]
      .filter((name) => params.some((p) => p.name === name)),
    reasons,
  };
}
