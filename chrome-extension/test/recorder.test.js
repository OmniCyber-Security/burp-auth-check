import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Recorder } from '../src/lib/recorder.js';

const req = (requestId, url, extra = {}) => ({
  requestId, type: 'Document', wallTime: 1_760_000_000,
  request: { method: 'GET', url, headers: { Accept: 'text/html' } }, ...extra,
});

test('a redirect chain becomes one exchange per hop, linked to its predecessor', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'https://a.test/login', {
    request: { method: 'POST', url: 'https://a.test/login', headers: {}, postData: 'u=x', hasPostData: true },
  }));
  r.onRequestWillBeSent(req('1', 'https://a.test/home', {
    redirectResponse: { status: 302, headers: { Location: '/home' }, mimeType: '' },
  }));
  r.onResponseReceived({ requestId: '1', response: { status: 200, headers: {}, mimeType: 'text/html' } });
  const [post, home] = r.exchanges();
  assert.equal(post.method, 'POST');
  assert.equal(post.status, 302);
  assert.equal(post.requestBody, 'u=x');
  assert.equal(home.status, 200);
  assert.equal(home.redirectedFrom, post.id);
});

test('ExtraInfo supplies the real Cookie and every Set-Cookie, matched to the right hop', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'https://a.test/login'));
  // ExtraInfo can arrive before or after the main event; order must not matter.
  r.onResponseExtraInfo({ requestId: '1', statusCode: 302,
    headers: { 'Set-Cookie': 'a=1; Path=/\nb=2; Path=/', Location: '/next' } });
  r.onRequestExtraInfo({ requestId: '1', headers: { Cookie: 'pre=0', Accept: 'text/html' } });
  r.onRequestWillBeSent(req('1', 'https://a.test/next', {
    redirectResponse: { status: 302, headers: { Location: '/next' }, mimeType: '' },
  }));
  r.onRequestExtraInfo({ requestId: '1', headers: { Cookie: 'pre=0; a=1; b=2' } });
  r.onResponseReceived({ requestId: '1', response: { status: 200, headers: { 'Content-Type': 'text/html' }, mimeType: 'text/html' } });
  r.onResponseExtraInfo({ requestId: '1', statusCode: 200, headers: { 'Content-Type': 'text/html' } });

  const [first, second] = r.exchanges();
  assert.deepEqual(first.requestHeaders.find(([n]) => n === 'Cookie'), ['Cookie', 'pre=0']);
  assert.deepEqual(first.responseHeaders.filter(([n]) => n === 'Set-Cookie').map(([, v]) => v),
    ['a=1; Path=/', 'b=2; Path=/']);
  assert.deepEqual(second.requestHeaders.find(([n]) => n === 'Cookie'), ['Cookie', 'pre=0; a=1; b=2']);
  assert.equal(second.status, 200);
});

test('assets, preflights and other noise are not recorded at all', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'https://a.test/app.js', { type: 'Script' }));
  r.onRequestWillBeSent(req('2', 'https://a.test/api', { type: 'Fetch',
    request: { method: 'OPTIONS', url: 'https://a.test/api', headers: {} } }));
  r.onRequestWillBeSent(req('3', 'https://a.test/logo.png', { type: 'Image' }));
  assert.equal(r.exchanges().length, 0);
});

test('bodies are only requested for textual responses', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'https://a.test/'));
  r.onResponseReceived({ requestId: '1', response: { status: 200, headers: {}, mimeType: 'text/html' } });
  r.onRequestWillBeSent(req('2', 'https://a.test/file', { type: 'Other' }));
  r.onResponseReceived({ requestId: '2', response: { status: 200, headers: {}, mimeType: 'application/pdf' } });
  assert.ok(r.onLoadingFinished({ requestId: '1', encodedDataLength: 100 }));
  assert.equal(r.onLoadingFinished({ requestId: '2', encodedDataLength: 100 }), null);
});

test('same requestId on different targets (iframes) does not collide', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'https://a.test/'), undefined);
  r.onRequestWillBeSent(req('1', 'https://idp.test/'), 'session-2');
  assert.deepEqual(r.exchanges().map((x) => x.url), ['https://a.test/', 'https://idp.test/']);
  assert.equal(r.exchanges()[1].redirectedFrom, null);
});

test('typed values arrive through the binding; junk is ignored', () => {
  const r = new Recorder();
  r.onBinding(JSON.stringify({ name: 'password', type: 'password', value: 'pw' }));
  r.onBinding('not json');
  r.onBinding(JSON.stringify({ name: 'x' }));
  assert.equal(r.inputs.length, 1);
});

test('an internal (HSTS) redirect does not shift the raw headers onto the wrong hop', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'http://a.test/cb'));
  // Chrome upgrades to https itself: no network, so no ExtraInfo for this hop.
  r.onRequestWillBeSent(req('1', 'https://a.test/cb', {
    redirectResponse: { status: 307, statusText: 'Internal Redirect',
      headers: { Location: 'https://a.test/cb', 'Non-Authoritative-Reason': 'HSTS' }, mimeType: '' },
  }));
  r.onRequestExtraInfo({ requestId: '1', headers: { Cookie: 'sid=1' } });
  r.onResponseExtraInfo({ requestId: '1', statusCode: 302, headers: { 'Set-Cookie': 'app=2; Path=/', Location: '/home' } });
  r.onRequestWillBeSent(req('1', 'https://a.test/home', {
    redirectResponse: { status: 302, headers: { Location: '/home' }, mimeType: '' },
  }));
  r.onRequestExtraInfo({ requestId: '1', headers: { Cookie: 'sid=1; app=2' } });
  r.onResponseReceived({ requestId: '1', response: { status: 200, headers: {}, mimeType: 'text/html' } });
  r.onResponseExtraInfo({ requestId: '1', statusCode: 200, headers: { 'Content-Type': 'text/html' } });

  const [upgrade, cb, home] = r.exchanges();
  assert.equal(upgrade.status, 307);
  assert.equal(upgrade.requestHeaders.find(([n]) => n === 'Cookie'), undefined);
  assert.equal(cb.status, 302);
  assert.deepEqual(cb.responseHeaders.find(([n]) => n === 'Set-Cookie'), ['Set-Cookie', 'app=2; Path=/']);
  assert.deepEqual(cb.requestHeaders.find(([n]) => n === 'Cookie'), ['Cookie', 'sid=1']);
  assert.deepEqual(home.requestHeaders.find(([n]) => n === 'Cookie'), ['Cookie', 'sid=1; app=2']);
  assert.equal(home.status, 200);
});

test('a revalidated response is recorded as the 200 the page saw, not the 304 on the wire', () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('1', 'https://a.test/login'));
  r.onResponseReceived({ requestId: '1', response: { status: 200, headers: {}, mimeType: 'text/html' } });
  r.onResponseExtraInfo({ requestId: '1', statusCode: 304, headers: { ETag: '"x"' } });
  assert.equal(r.exchanges()[0].status, 200);
});

test("a cross-origin frame's navigation finishing on the frame's own session is joined up", () => {
  const r = new Recorder();
  r.onRequestWillBeSent(req('NAV-1', 'https://idp.test/login'), undefined);
  r.onResponseExtraInfo({ requestId: 'NAV-1', statusCode: 200, headers: { 'Set-Cookie': 'idp=1' } }, 'child');
  r.onResponseReceived({ requestId: 'NAV-1', response: { status: 200, headers: {}, mimeType: 'text/html' } }, 'child');
  const hop = r.onLoadingFinished({ requestId: 'NAV-1', encodedDataLength: 10 }, 'child');
  assert.ok(hop, 'the body should be fetched');
  const [x] = r.exchanges();
  assert.equal(x.status, 200);
  assert.deepEqual(x.responseHeaders, [['Set-Cookie', 'idp=1']]);
});
