// Review a recording and turn it into an Auth Check script and identities.
//
// Everything shown here comes from the target application (URLs, headers,
// bodies), so it only ever reaches the page through textContent.

import { analyse } from './lib/analyse.js';
import { generateScript } from './lib/groovy.js';
import { identityExport } from './lib/identities.js';
import { listCaptures, loadCapture, saveCapture, deleteCapture } from './lib/store.js';
import { header } from './lib/http.js';

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key === 'class') el.className = value;
    else if (key in el && typeof value !== 'string') el[key] = value;
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

let capture = null;
let analysis = null;
let script = '';
let selected = null;
let saveTimer = null;

const options = () => (capture.options ||= {});

function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => saveCapture(capture).catch(console.error), 300);
}

function update() {
  analysis = analyse(capture, options());
  script = generateScript(analysis.plan, { generatedAt: new Date(capture.startedAt).toISOString().slice(0, 10) });
  ensureIdentities();
  renderRequests();
  renderDetail();
  renderScript();
  renderParams();
  renderSession();
  renderIdentities();
  renderWarnings();
}

function change(mutate) {
  mutate(options());
  persist();
  update();
}

// -- captures -----------------------------------------------------------------

async function loadList(preferred) {
  const list = await listCaptures();
  const select = $('captures');
  select.replaceChildren(...list.map((c) => h('option', { value: c.id },
    `${c.title || c.tabUrl} — ${new Date(c.startedAt).toLocaleString()}`)));
  $('empty').hidden = list.length > 0;
  $('main').hidden = list.length === 0;
  $('delete').hidden = list.length === 0;
  if (!list.length) {
    $('meta').textContent = '';
    return;
  }
  const id = list.some((c) => c.id === preferred) ? preferred : list[0].id;
  select.value = id;
  await open(id);
}

async function open(id) {
  capture = await loadCapture(id);
  if (!capture) return;
  selected = null;
  history.replaceState(null, '', `#${id}`);
  $('meta').textContent = `${capture.exchanges.length} requests · ${capture.inputs.length} typed values · ${capture.tabUrl}`;
  update();
}

$('captures').addEventListener('change', (e) => open(e.target.value));
$('delete').addEventListener('click', async () => {
  if (!capture || !confirm('Delete this recording? It holds the credentials and session tokens it captured.')) return;
  await deleteCapture(capture.id);
  await loadList();
});
$('showAll').addEventListener('change', () => renderRequests());

// -- requests -----------------------------------------------------------------

function renderRequests() {
  const showAll = $('showAll').checked;
  const rows = analysis.exchanges.filter((x) => showAll || x.included || x.marker || x.credentialBearing
    || x.setsCookies.length || x.dynamic.length || x.id === selected);
  const body = $('requests').tBodies[0];
  body.replaceChildren(...rows.map((x) => {
    const chips = [];
    if (x.marker) chips.push(h('span', { class: 'chip marker' }, 'proves the session'));
    if (x.usesParams.length) chips.push(h('span', { class: 'chip cred' }, `sends ${x.usesParams.join(', ')}`));
    if (x.setsCookies.length) chips.push(h('span', { class: 'chip' }, `sets ${x.setsCookies.join(', ')}`));
    for (const d of x.dynamic.slice(0, 4)) chips.push(h('span', { class: 'chip' }, `${d.name} ← #${d.from + 1}`));
    if (x.dynamic.length > 4) chips.push(h('span', { class: 'chip' }, `+${x.dynamic.length - 4} more`));
    const url = new URL(x.url);
    return h('tr', {
      class: [x.included ? '' : 'excluded', x.id === selected ? 'selected' : ''].join(' '),
      onclick: (e) => {
        if (e.target.closest('input')) return;
        selected = selected === x.id ? null : x.id;
        renderRequests();
        renderDetail();
      },
    },
    h('td', {}, h('input', {
      type: 'checkbox', checked: x.included,
      title: x.required ? 'The session depends on this request' : 'Not needed for the session',
      onchange: (e) => change((o) => {
        o.include ||= {};
        // Back to automatic when the tick matches what the analysis chose.
        if (e.target.checked === x.required) delete o.include[x.id];
        else o.include[x.id] = e.target.checked;
      }),
    })),
    h('td', {}, h('input', {
      type: 'radio', name: 'marker', checked: x.marker,
      onchange: () => change((o) => { o.markerId = x.id; delete o.cookies; delete o.headers; }),
    })),
    h('td', { class: 'nowrap' }, x.index + 1, x.step ? h('span', { class: 'muted' }, ` · step ${x.step}`) : null),
    h('td', { class: 'mono' }, x.method),
    h('td', { class: 'url mono' }, h('span', { class: 'host' }, url.host), url.pathname + url.search),
    h('td', { class: `status-${String(x.status)[0]}` }, x.status),
    h('td', {}, chips));
  }));
}

function renderDetail() {
  const detail = $('detail');
  const x = selected && capture.exchanges.find((e) => e.id === selected);
  detail.hidden = !x;
  if (!x) return;
  const headers = (list) => list.map(([n, v]) => `${n}: ${v}`).join('\n');
  const body = (text, base64) => {
    if (text == null) return '(not captured)';
    if (base64) return '(binary)';
    return text.length > 20000 ? `${text.slice(0, 20000)}\n… ${text.length - 20000} more characters` : text;
  };
  detail.replaceChildren(...[
    h('h4', {}, `${x.method} ${x.url}`),
    h('pre', {}, headers(x.requestHeaders)),
    x.requestBody ? h('pre', {}, body(x.requestBody)) : null,
    h('h4', {}, `HTTP ${x.status} ${x.statusText || ''} · ${x.mimeType || header(x.responseHeaders, 'content-type') || ''}`),
    h('pre', {}, headers(x.responseHeaders)),
    h('pre', {}, body(x.responseBody, x.responseBodyBase64)),
  ].filter(Boolean));
}

// -- script ---------------------------------------------------------------------

function renderScript() {
  $('script').textContent = script;
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const fileStem = () => {
  try {
    return `auth-check-${new URL(analysis.plan.baseOrigin).host.replace(/[^a-z0-9.-]/gi, '_')}`;
  } catch {
    return 'auth-check-recorded';
  }
};

$('copyScript').addEventListener('click', async () => {
  await navigator.clipboard.writeText(script);
  $('copied').textContent = 'Copied';
  setTimeout(() => { $('copied').textContent = ''; }, 1500);
});
$('downloadScript').addEventListener('click', () => download(`${fileStem()}.groovy`, script, 'text/plain'));
$('downloadIdentities').addEventListener('click', () => {
  const missing = [];
  for (const identity of options().identities) {
    for (const param of declaredParams().filter((p) => p.required)) {
      if (!identity.credentials[param.name]) missing.push(`${identity.name}: ${param.label || param.name}`);
    }
  }
  if (missing.length && !confirm(`These required values are empty, and Burp will refuse to log in until they are filled:\n\n${
    missing.join('\n')}\n\nDownload anyway?`)) return;
  const file = identityExport(script, analysis.plan, options().identities);
  download(`${fileStem()}-identities.json`, JSON.stringify(file, null, 2), 'application/json');
});

// -- credentials ----------------------------------------------------------------

function editableParams() {
  return options().params || analysis.params.map((p) => ({ ...p }));
}

function renderParams() {
  const params = analysis.params;
  const body = $('params').tBodies[0];
  if (!params.length) {
    body.replaceChildren(h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'No typed value was found in any request.')));
    return;
  }
  const edit = (index, mutate) => change((o) => {
    o.params = editableParams();
    mutate(o.params[index], o.params);
  });
  body.replaceChildren(...params.map((p, index) => {
    const shown = p.kind === 'totp' ? `code ${p.code} → generated from the secret` : p.value;
    const value = h('span', { class: 'mono' }, p.type === 'SECRET' && p.kind !== 'totp' ? '•'.repeat(Math.min(12, shown.length)) : shown);
    const reveal = p.type === 'SECRET' && p.kind !== 'totp'
      ? h('button', { class: 'reveal', onclick: () => { value.textContent = shown; } }, 'show') : null;
    return h('tr', {},
      h('td', {}, h('input', { value: p.name, onchange: (e) => edit(index, (q) => {
        const renamed = e.target.value.replace(/[^A-Za-z0-9_]/g, '') || q.name;
        // Identities typed against the old name keep their values.
        for (const identity of options().identities || []) {
          if (q.name in identity.credentials && !(renamed in identity.credentials)) {
            identity.credentials[renamed] = identity.credentials[q.name];
            delete identity.credentials[q.name];
          }
        }
        q.name = renamed;
      }) })),
      h('td', {}, h('select', { onchange: (e) => edit(index, (q) => { q.type = e.target.value; }) },
        ...['STRING', 'SECRET'].map((t) => h('option', { value: t, selected: p.type === t }, t)))),
      h('td', {}, h('input', { type: 'checkbox', checked: p.required, onchange: (e) => edit(index, (q) => { q.required = e.target.checked; }) })),
      h('td', {}, value, reveal),
      h('td', { class: 'muted' }, p.field || ''),
      h('td', {}, h('button', { class: 'danger', onclick: () => edit(index, (q, all) => all.splice(index, 1)) }, 'Remove')));
  }));
}

$('addParam').addEventListener('click', () => {
  const value = $('newValue').value;
  const name = $('newName').value.replace(/[^A-Za-z0-9_]/g, '');
  if (!value || !name) return;
  change((o) => {
    o.params = editableParams();
    o.params.push({ name, type: /pass|secret|token|key|pin/i.test(name) ? 'SECRET' : 'STRING', required: false,
      value, field: '(added by hand)', label: name, kind: 'credential' });
  });
  $('newValue').value = '';
  $('newName').value = '';
});

// -- session --------------------------------------------------------------------

function renderSession() {
  const marker = analysis.exchanges.find((x) => x.marker);
  $('sessionMarker').replaceChildren(marker
    ? h('p', {}, 'Proof request: ', h('span', { class: 'mono' }, `#${marker.index + 1} ${marker.method} ${marker.url}`))
    : h('p', { class: 'warn' }, 'No proof request chosen. Pick one in the Proof column.'));
  const toggles = (items, key, describe) => (items.length
    ? items.map((item) => h('label', {},
      h('input', { type: 'checkbox', checked: item.selected,
        onchange: (e) => change((o) => { o[key] = { ...(o[key] || {}), [item.name]: e.target.checked }; }) }),
      h('span', { class: 'mono' }, item.name), h('span', { class: 'muted' }, describe(item))))
    : [h('p', { class: 'muted' }, 'None sent.')]);
  const all = analysis.material.all || { cookies: [], headers: [] };
  $('sessionCookies').replaceChildren(...toggles(all.cookies, 'cookies',
    (c) => (c.auto ? 'set during the login' : 'already in the browser — not produced by the login')));
  $('sessionHeaders').replaceChildren(...toggles(all.headers, 'headers',
    (hd) => (hd.auto ? 'produced by the login' : 'constant — usually already on the request')));

  const origins = [...new Set(analysis.exchanges.filter((x) => x.included).map((x) => new URL(x.url).origin))];
  const base = analysis.plan.baseOrigin;
  if (base && !origins.includes(base)) origins.unshift(base);
  $('baseOrigin').replaceChildren(...origins.map((o) => h('option', { value: o, selected: o === base }, o)));
  $('baseOrigin').onchange = (e) => change((o) => { o.baseOrigin = e.target.value; });
}

// -- identities -----------------------------------------------------------------

function declaredParams() {
  const names = [...script.matchAll(/^\s*param '([^']+)'/gm)].map((m) => m[1]);
  return names.map((name) => analysis.params.find((p) => p.name === name)
    || { name, label: name === 'base' ? 'Base URL' : name, type: 'STRING', required: false });
}

function ensureIdentities() {
  const o = options();
  if (!o.identities) {
    const credentials = {};
    for (const p of analysis.params) if (p.kind === 'credential') credentials[p.name] = p.value;
    o.identities = [{ name: 'Recorded user', credentials }];
  }
}

function renderIdentities() {
  const params = declaredParams();
  const table = $('identities');
  table.tHead.replaceChildren(h('tr', {}, h('th', {}, 'Identity name'),
    ...params.map((p) => h('th', {}, p.label || p.name, p.required ? ' *' : '')), h('th', {})));
  const edit = (mutate) => { mutate(options().identities); persist(); };
  table.tBodies[0].replaceChildren(...options().identities.map((identity, index) => h('tr', {},
    h('td', {}, h('input', { value: identity.name, onchange: (e) => edit(() => { identity.name = e.target.value; }) })),
    ...params.map((p) => h('td', {}, h('input', {
      type: p.type === 'SECRET' ? 'password' : 'text',
      autocomplete: 'off',
      value: identity.credentials[p.name] ?? '',
      placeholder: p.name === 'base' ? analysis.plan.baseOrigin || '' : p.kind === 'totp' ? 'base32 secret' : '',
      onchange: (e) => edit(() => { identity.credentials[p.name] = e.target.value; }),
    }))),
    h('td', {}, h('button', { class: 'danger', onclick: () => { edit((all) => all.splice(index, 1)); renderIdentities(); } }, 'Remove')))));
}

$('addIdentity').addEventListener('click', () => {
  const list = options().identities;
  list.push({ name: `User ${list.length + 1}`, credentials: {} });
  persist();
  renderIdentities();
});

// -- warnings -------------------------------------------------------------------

function renderWarnings() {
  const warnings = analysis.warnings;
  $('warnCount').textContent = warnings.length || '';
  $('warnCount').hidden = !warnings.length;
  $('warnings').replaceChildren(...(warnings.length
    ? warnings.map((w) => h('p', { class: 'warn' }, w))
    : [h('p', { class: 'muted' }, 'Nothing to flag.')]));
}

// -- tabs -----------------------------------------------------------------------

for (const tab of document.querySelectorAll('[role=tab]')) {
  tab.addEventListener('click', () => {
    for (const other of document.querySelectorAll('[role=tab]')) {
      other.setAttribute('aria-selected', String(other === tab));
      $(`tab-${other.dataset.tab}`).hidden = other !== tab;
    }
  });
}

loadList(location.hash.slice(1)).catch((error) => {
  document.body.append(h('p', { class: 'warn' }, `Could not load recordings: ${error.message}`));
});
