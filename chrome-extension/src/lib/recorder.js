// Turns the Chrome DevTools Protocol's Network events into whole exchanges.
//
// CDP reports a request in pieces, and the pieces that matter most for a login
// arrive separately: the Cookie header the browser actually sent only appears in
// requestWillBeSentExtraInfo, and Set-Cookie only in responseReceivedExtraInfo.
// A redirect chain also shares one requestId, so each hop has to be split back
// out, and the ExtraInfo events matched to the hop they describe.
//
// No chrome.* calls in here: the background worker feeds events in and asks for
// bodies, which keeps this file testable under node.

import { headerObjectToList } from './http.js';

const KEPT_TYPES = new Set(['Document', 'XHR', 'Fetch', 'Other']);
const TEXTUAL = /^(text\/|application\/(json|xml|xhtml|javascript|x-www-form-urlencoded|[\w.+-]*\+(json|xml)))/i;
export const MAX_BODY = 2 * 1024 * 1024;

export class Recorder {
  constructor() {
    this.seq = 0;
    /** key -> { hops: Exchange[], reqExtra: [], respExtra: [] } */
    this.chains = new Map();
    this.inputs = [];
  }

  key(sessionId, requestId) {
    return `${sessionId || ''}|${requestId}`;
  }

  chain(key) {
    let chain = this.chains.get(key);
    if (!chain) {
      chain = { hops: [], reqExtra: [], respExtra: [], ignored: false };
      this.chains.set(key, chain);
    }
    return chain;
  }

  /**
   * A cross-origin iframe's navigation starts on the parent's session and
   * finishes on the frame's own, so an event for a requestId this session has
   * not seen belongs to the chain another session started.
   */
  find(sessionId, requestId) {
    const exact = this.chains.get(this.key(sessionId, requestId));
    if (exact) return exact;
    for (const [key, chain] of this.chains) {
      if (key.slice(key.indexOf('|') + 1) === requestId) return chain;
    }
    return null;
  }

  findOrCreate(sessionId, requestId) {
    return this.find(sessionId, requestId) || this.chain(this.key(sessionId, requestId));
  }

  onRequestWillBeSent(p, sessionId) {
    const chain = p.redirectResponse ? this.findOrCreate(sessionId, p.requestId)
      : this.chain(this.key(sessionId, p.requestId));
    const type = p.type || 'Other';
    if (!KEPT_TYPES.has(type) || p.request.method === 'OPTIONS') {
      chain.ignored = true;
      return null;
    }
    if (p.redirectResponse && chain.hops.length) {
      this.applyResponse(chain, chain.hops[chain.hops.length - 1], p.redirectResponse);
    }
    const request = p.request;
    const hop = {
      id: `x${++this.seq}`,
      seq: this.seq,
      time: p.wallTime ? Math.round(p.wallTime * 1000) : Date.now(),
      method: request.method,
      url: request.url + (request.urlFragment || ''),
      resourceType: type,
      requestHeaders: headerObjectToList(request.headers),
      baseRequestHeaders: headerObjectToList(request.headers),
      requestBody: postData(request),
      needsPostData: Boolean(request.hasPostData && postData(request) == null),
      status: 0,
      statusText: '',
      responseHeaders: [],
      responseBody: null,
      responseBodyBase64: false,
      mimeType: '',
      redirectedFrom: chain.hops.length ? chain.hops[chain.hops.length - 1].id : null,
      failed: null,
      fromCache: false,
    };
    chain.hops.push(hop);
    this.mergeExtras(chain);
    return hop;
  }

  onRequestExtraInfo(p, sessionId) {
    const chain = this.findOrCreate(sessionId, p.requestId);
    chain.reqExtra.push(p);
    this.mergeExtras(chain);
  }

  onResponseReceived(p, sessionId) {
    const chain = this.find(sessionId, p.requestId);
    if (!chain || chain.ignored || !chain.hops.length) return;
    this.applyResponse(chain, chain.hops[chain.hops.length - 1], p.response);
  }

  onResponseExtraInfo(p, sessionId) {
    const chain = this.findOrCreate(sessionId, p.requestId);
    chain.respExtra.push(p);
    this.mergeExtras(chain);
  }

  /** @returns the hop whose body should now be fetched, or null */
  onLoadingFinished(p, sessionId) {
    const chain = this.find(sessionId, p.requestId);
    if (!chain || chain.ignored || !chain.hops.length) return null;
    const last = chain.hops[chain.hops.length - 1];
    if (!TEXTUAL.test(last.mimeType || '') || (p.encodedDataLength || 0) > MAX_BODY) return null;
    return last;
  }

  onLoadingFailed(p, sessionId) {
    const chain = this.find(sessionId, p.requestId);
    if (!chain || chain.ignored || !chain.hops.length) return;
    chain.hops[chain.hops.length - 1].failed = p.errorText || 'failed';
  }

  onBinding(payload) {
    try {
      const input = JSON.parse(payload);
      if (input && typeof input.value === 'string') this.inputs.push(input);
    } catch {
      // A page cannot reach the binding (it lives in an isolated world), so a
      // malformed payload is a bug in our own hook, not something to act on.
    }
  }

  applyResponse(chain, hop, response) {
    const headers = headerObjectToList(response.headers);
    hop.baseStatus = response.status;
    hop.statusText = response.statusText || '';
    hop.mimeType = response.mimeType || '';
    hop.fromCache = Boolean(response.fromDiskCache || response.fromServiceWorker || response.fromPrefetchCache);
    hop.baseResponseHeaders = headers;
    // Chrome answers some redirects itself (HSTS upgrades, extension or
    // policy rewrites) and some responses from cache. Neither touched the
    // network, so neither has ExtraInfo events to claim.
    hop.offNetwork = hop.fromCache || hop.statusText === 'Internal Redirect'
      || headers.some(([name]) => name.toLowerCase() === 'non-authoritative-reason');
    hop.hasResponse = true;
    this.mergeExtras(chain);
  }

  /**
   * ExtraInfo events carry no hop index, so they are matched to hops by
   * position among the hops that went over the network. Recomputed from
   * scratch on every event, because whether a hop went over the network is
   * only known once its response arrives -- after the ExtraInfo may have.
   */
  mergeExtras(chain) {
    for (const hop of chain.hops) {
      hop.requestHeaders = hop.baseRequestHeaders;
      if (hop.hasResponse) {
        hop.responseHeaders = hop.baseResponseHeaders;
        hop.status = hop.baseStatus;
      }
    }
    chain.hops.filter((hop) => !hop.offNetwork).forEach((hop, index) => {
      const extra = chain.reqExtra[index];
      if (extra) hop.requestHeaders = headerObjectToList(extra.headers);
    });
    chain.hops.filter((hop) => hop.hasResponse && !hop.offNetwork).forEach((hop, index) => {
      const extra = chain.respExtra[index];
      if (!extra) return;
      hop.responseHeaders = headerObjectToList(extra.headers);
      // A revalidated response reads 304 on the wire and 200 to the page. The
      // script never sends If-None-Match, so the 200 is what it will get.
      if (extra.statusCode && extra.statusCode !== 304) hop.status = extra.statusCode;
    });
  }

  setBody(hop, body, base64) {
    hop.responseBody = body;
    hop.responseBodyBase64 = Boolean(base64);
  }

  setPostData(hop, body) {
    hop.requestBody = body;
    hop.needsPostData = false;
  }

  exchanges() {
    const all = [];
    for (const chain of this.chains.values()) {
      if (chain.ignored) continue;
      for (const hop of chain.hops) {
        const { hasResponse, needsPostData, baseRequestHeaders, baseResponseHeaders, baseStatus, ...clean } = hop;
        all.push(clean);
      }
    }
    return all.sort((a, b) => a.seq - b.seq);
  }
}

function postData(request) {
  if (typeof request.postData === 'string') return request.postData;
  if (Array.isArray(request.postDataEntries) && request.postDataEntries.length) {
    try {
      return request.postDataEntries.map((entry) => {
        const binary = atob(entry.bytes || '');
        return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
      }).join('');
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Runs inside the page, in an isolated world the page's own scripts cannot see,
 * and reports what was typed into each field. The analyser needs the literal
 * credentials to recognise them in request bodies and swap in `creds.*`.
 */
export function pageHook(bindingName) {
  if (globalThis.__authCheckHooked) return;
  globalThis.__authCheckHooked = true;
  const SKIP = new Set(['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image', 'reset', 'range', 'color']);
  const last = new WeakMap();

  const labelOf = (el) => {
    try {
      if (el.labels && el.labels.length) return el.labels[0].textContent.trim().slice(0, 80);
    } catch { /* detached */ }
    return (el.getAttribute('aria-label') || '').slice(0, 80);
  };

  const report = (el, reason) => {
    if (!el || !(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) return;
    const type = (el.type || 'text').toLowerCase();
    if (SKIP.has(type) || !el.value) return;
    if (last.get(el) === el.value && reason !== 'submit') return;
    last.set(el, el.value);
    try {
      globalThis[bindingName](JSON.stringify({
        name: el.name || '',
        id: el.id || '',
        type,
        autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
        placeholder: el.placeholder || '',
        label: labelOf(el),
        value: el.value,
        reason,
        url: location.href,
        time: Date.now(),
      }));
    } catch { /* binding gone: recording stopped */ }
  };

  const targetOf = (event) => (event.composedPath ? event.composedPath()[0] : event.target);
  const reportAll = (root, reason) => {
    const scope = root && root.querySelectorAll ? root : document;
    for (const el of scope.querySelectorAll('input, textarea')) report(el, reason);
  };

  document.addEventListener('change', (e) => report(targetOf(e), 'change'), true);
  document.addEventListener('input', (e) => {
    const el = targetOf(e);
    clearTimeout(el.__authCheckTimer);
    el.__authCheckTimer = setTimeout(() => report(el, 'input'), 400);
  }, true);
  // Submitting reports every field, which also catches password-manager
  // autofill that fired no input event of its own.
  document.addEventListener('submit', (e) => reportAll(e.target, 'submit'), true);
  document.addEventListener('click', (e) => {
    const el = targetOf(e);
    const button = el && el.closest && el.closest('button, input[type=submit], [role=button]');
    if (button) reportAll(button.form || document, 'submit');
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') reportAll(document, 'submit');
  }, true);
}
