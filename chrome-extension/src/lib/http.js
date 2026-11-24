// Parsing helpers shared by the recorder and the analyser. Pure functions only:
// everything here runs under `node --test` as well as in the browser.

/** Case-insensitive lookup of the first header with this name. */
export function header(headers, name) {
  const lower = name.toLowerCase();
  for (const [key, value] of headers || []) {
    if (key.toLowerCase() === lower) return value;
  }
  return null;
}

/** Every value of a header that may repeat (Set-Cookie). */
export function headerValues(headers, name) {
  const lower = name.toLowerCase();
  return (headers || []).filter(([key]) => key.toLowerCase() === lower).map(([, v]) => v);
}

/**
 * CDP hands headers over as an object, joining repeated ones with "\n".
 * Splitting them back is what keeps two Set-Cookie lines two cookies.
 */
export function headerObjectToList(object) {
  const list = [];
  for (const [name, value] of Object.entries(object || {})) {
    for (const line of String(value).split('\n')) {
      list.push([name, line]);
    }
  }
  return list;
}

export function safeDecode(value) {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

/** `a=1&b=2` into ordered [name, value] pairs, decoded. */
export function parseQuery(query) {
  if (!query) return [];
  return query.split('&').filter(Boolean).map((pair) => {
    const eq = pair.indexOf('=');
    return eq < 0
      ? [safeDecode(pair), '']
      : [safeDecode(pair.slice(0, eq)), safeDecode(pair.slice(eq + 1))];
  });
}

export function splitUrl(url) {
  const parsed = new URL(url);
  return {
    origin: parsed.origin,
    host: parsed.hostname,
    path: parsed.pathname,
    query: parsed.search ? parsed.search.slice(1) : '',
  };
}

/** The Cookie request header as ordered [name, value] pairs. */
export function parseCookieHeader(value) {
  if (!value) return [];
  return value.split(';').map((part) => part.trim()).filter(Boolean).map((part) => {
    const eq = part.indexOf('=');
    return eq < 0 ? [part, ''] : [part.slice(0, eq).trim(), part.slice(eq + 1).trim()];
  });
}

/** One Set-Cookie line: name, value, and the attributes that decide where it goes. */
export function parseSetCookie(line) {
  const parts = line.split(';');
  const first = parts.shift() || '';
  const eq = first.indexOf('=');
  const cookie = {
    name: (eq < 0 ? first : first.slice(0, eq)).trim(),
    value: eq < 0 ? '' : first.slice(eq + 1).trim(),
    domain: null,
    path: null,
    expired: false,
  };
  for (const attribute of parts) {
    const [rawKey, ...rest] = attribute.split('=');
    const key = rawKey.trim().toLowerCase();
    const value = rest.join('=').trim();
    if (key === 'domain') cookie.domain = value.replace(/^\./, '').toLowerCase();
    if (key === 'path') cookie.path = value;
    if (key === 'max-age' && Number(value) <= 0) cookie.expired = true;
    if (key === 'expires') {
      const when = Date.parse(value);
      if (!Number.isNaN(when) && when < Date.now() - 1000) cookie.expired = true;
    }
  }
  return cookie;
}

/** Whether a cookie set by `setterHost` with this Domain attribute is sent to `host`. */
export function cookieApplies(cookie, setterHost, host) {
  if (!cookie.domain) return setterHost === host;
  return host === cookie.domain || host.endsWith('.' + cookie.domain);
}

export function contentType(headers) {
  return (header(headers, 'content-type') || '').toLowerCase();
}

export function isFormBody(headers) {
  return contentType(headers).startsWith('application/x-www-form-urlencoded');
}

export function isJsonType(type) {
  return /[/+]json\b/.test(type || '');
}

export function tryJson(text) {
  if (text == null) return undefined;
  const trimmed = String(text).trim();
  if (!trimmed || !'{['.includes(trimmed[0])) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

/** Every string/number leaf of parsed JSON with the path that reaches it. */
export function jsonLeaves(value, path = [], out = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => jsonLeaves(item, [...path, index], out));
  } else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) jsonLeaves(item, [...path, key], out);
  } else if (typeof value === 'string' || typeof value === 'number') {
    out.push({ path, value: String(value) });
  }
  return out;
}

const HTML_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

export function htmlUnescape(text) {
  return text.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (whole, entity) => {
    if (entity[0] === '#') {
      const code = entity[1] === 'x' || entity[1] === 'X'
        ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    return HTML_ENTITIES[entity.toLowerCase()] ?? whole;
  });
}

/**
 * The spellings a value might take inside a response body, each with the
 * decoding that turns the captured text back into the value itself.
 */
export function encodings(value) {
  const forms = [{ text: value, decode: null }];
  const add = (text, decode) => {
    if (text !== value && !forms.some((form) => form.text === text)) forms.push({ text, decode });
  };
  add(value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;'), 'html');
  add(value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#x27;').replace(/\//g, '&#x2F;'), 'html');
  add(value.replace(/&/g, '&amp;'), 'html');
  add(encodeURIComponent(value), 'url');
  add(value.replace(/\//g, '\\/'), 'json');
  return forms;
}

export function decodeBase64(text) {
  try {
    if (typeof atob === 'function') {
      const binary = atob(text);
      const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    }
  } catch {
    return null;
  }
  return null;
}

const STATIC_EXTENSIONS = /\.(png|jpe?g|gif|svg|ico|webp|avif|css|js|mjs|map|woff2?|ttf|eot|otf|mp4|webm|mp3)$/i;

export function looksStatic(url) {
  try {
    return STATIC_EXTENSIONS.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

/** Mirrors Text.looksSecret in the Burp extension, so both agree on masking. */
export function looksSecret(name) {
  const lower = String(name || '').toLowerCase();
  return ['pass', 'secret', 'token', 'key', 'otp', 'pin', 'credential'].some((w) => lower.includes(w));
}
