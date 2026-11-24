// Service worker: attaches the DevTools protocol to one tab while the tester
// logs in, and saves what it saw as a capture for the editor.
//
// chrome.debugger is used rather than webRequest because a login needs the
// parts webRequest hides: response bodies (CSRF tokens, form actions, JSON
// tokens) and the Cookie / Set-Cookie headers as they were actually sent.
// Chrome shows its "is debugging this browser" bar for as long as it runs,
// which is the honest signal that everything in the tab is being recorded.

import { Recorder, pageHook, MAX_BODY } from './lib/recorder.js';
import { saveCapture } from './lib/store.js';

const BINDING = '__authCheckRecorder';
const WORLD = 'auth-check-recorder';
const HOOK = `(${pageHook.toString()})(${JSON.stringify(BINDING)})`;

/** The one recording in progress, or null. */
let active = null;

const send = (target, method, params = {}) => chrome.debugger.sendCommand(target, method, params);

async function instrument(target) {
  await send(target, 'Network.enable', { maxPostDataSize: 65536, maxResourceBufferSize: MAX_BODY * 4,
    maxTotalBufferSize: MAX_BODY * 16 });
  await send(target, 'Runtime.enable').catch(() => {});
  await send(target, 'Runtime.addBinding', { name: BINDING, executionContextName: WORLD }).catch(() => {});
  await send(target, 'Page.enable').catch(() => {});
  await send(target, 'Page.addScriptToEvaluateOnNewDocument', { source: HOOK, worldName: WORLD }).catch(() => {});
}

async function hookCurrentDocument(target) {
  const { frameTree } = await send(target, 'Page.getFrameTree');
  const { executionContextId } = await send(target, 'Page.createIsolatedWorld',
    { frameId: frameTree.frame.id, worldName: WORLD });
  await send(target, 'Runtime.evaluate', { expression: HOOK, contextId: executionContextId });
}

async function start(tabId, { reload = true, clearCookies = false } = {}) {
  if (active) throw new Error('Already recording another tab. Stop that recording first.');
  const target = { tabId };
  await chrome.debugger.attach(target, '1.3');
  // The tab's URL comes from the debugger session rather than chrome.tabs, so
  // the extension needs no "tabs" permission to read every tab's address.
  const { targetInfo } = await send(target, 'Target.getTargetInfo');
  if (!/^https?:/.test(targetInfo.url || '')) {
    await chrome.debugger.detach(target).catch(() => {});
    throw new Error('Open the target site in this tab first.');
  }
  active = {
    tabId,
    recorder: new Recorder(),
    pending: new Set(),
    capture: {
      id: `cap-${Date.now().toString(36)}`,
      title: targetInfo.title || new URL(targetInfo.url).host,
      tabUrl: targetInfo.url,
      startedAt: Date.now(),
    },
  };
  try {
    await instrument(target);
    // Frames from other origins (an IdP in an iframe) run as their own targets.
    await send(target, 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true })
      .catch(() => {});
    if (clearCookies) {
      const { cookies } = await send(target, 'Network.getCookies', { urls: [targetInfo.url] });
      for (const c of cookies) {
        await send(target, 'Network.deleteCookies', { name: c.name, domain: c.domain, path: c.path });
      }
    }
    if (reload) {
      await send(target, 'Page.reload', { ignoreCache: true });
    } else {
      await hookCurrentDocument(target).catch(() => {});
    }
  } catch (error) {
    await chrome.debugger.detach(target).catch(() => {});
    active = null;
    throw error;
  }
  await chrome.action.setBadgeBackgroundColor({ color: '#d93025' });
  await chrome.action.setBadgeText({ tabId, text: 'REC' });
  return status();
}

async function stop({ detach = true } = {}) {
  if (!active) return null;
  const session = active;
  active = null;
  // Bodies are fetched asynchronously after each response; give the last ones
  // a moment rather than saving a login page without its CSRF token.
  await Promise.race([Promise.allSettled([...session.pending]), new Promise((r) => setTimeout(r, 3000))]);
  if (detach) await chrome.debugger.detach({ tabId: session.tabId }).catch(() => {});
  await chrome.action.setBadgeText({ tabId: session.tabId, text: '' }).catch(() => {});

  const capture = {
    ...session.capture,
    stoppedAt: Date.now(),
    exchanges: session.recorder.exchanges(),
    inputs: session.recorder.inputs,
  };
  await saveCapture(capture);
  await chrome.tabs.create({ url: chrome.runtime.getURL(`src/editor.html#${capture.id}`) });
  return capture.id;
}

function status() {
  if (!active) return { recording: false };
  return {
    recording: true,
    tabId: active.tabId,
    title: active.capture.title,
    startedAt: active.capture.startedAt,
    requests: active.recorder.exchanges().length,
    inputs: active.recorder.inputs.length,
  };
}

function track(promise) {
  if (!active) return;
  const pending = active.pending;
  pending.add(promise);
  promise.finally(() => pending.delete(promise));
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  if (!active || source.tabId !== active.tabId) return;
  const { recorder } = active;
  const sessionId = source.sessionId;
  const target = sessionId ? { tabId: source.tabId, sessionId } : { tabId: source.tabId };
  try {
    switch (method) {
      case 'Network.requestWillBeSent': {
        const hop = recorder.onRequestWillBeSent(params, sessionId);
        if (hop?.needsPostData) {
          track(send(target, 'Network.getRequestPostData', { requestId: params.requestId })
            .then(({ postData }) => recorder.setPostData(hop, postData)).catch(() => {}));
        }
        break;
      }
      case 'Network.requestWillBeSentExtraInfo':
        recorder.onRequestExtraInfo(params, sessionId);
        break;
      case 'Network.responseReceived':
        recorder.onResponseReceived(params, sessionId);
        break;
      case 'Network.responseReceivedExtraInfo':
        recorder.onResponseExtraInfo(params, sessionId);
        break;
      case 'Network.loadingFinished': {
        const hop = recorder.onLoadingFinished(params, sessionId);
        if (hop) {
          track(send(target, 'Network.getResponseBody', { requestId: params.requestId })
            .then(({ body, base64Encoded }) => recorder.setBody(hop, body, base64Encoded)).catch(() => {}));
        }
        break;
      }
      case 'Network.loadingFailed':
        recorder.onLoadingFailed(params, sessionId);
        break;
      case 'Runtime.bindingCalled':
        if (params.name === BINDING) recorder.onBinding(params.payload);
        break;
      case 'Target.attachedToTarget': {
        const child = { tabId: source.tabId, sessionId: params.sessionId };
        // A frame can hold frames of its own, so each child auto-attaches too.
        const setup = ['iframe', 'page'].includes(params.targetInfo.type)
          ? instrument(child).then(() => send(child, 'Target.setAutoAttach',
            { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }))
          : Promise.resolve();
        track(setup.catch(() => {}).then(() => send(child, 'Runtime.runIfWaitingForDebugger')).catch(() => {}));
        break;
      }
      default:
        break;
    }
  } catch (error) {
    console.error('Auth Check Recorder: failed to handle', method, error);
  }
});

chrome.debugger.onDetach.addListener((source) => {
  // The tester closed the tab or pressed Cancel on Chrome's debugging bar:
  // keep what was recorded rather than throwing it away.
  if (active && source.tabId === active.tabId) stop({ detach: false }).catch(console.error);
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  const run = async () => {
    switch (message.type) {
      case 'start': return start(message.tabId, message.options);
      case 'stop': return { captureId: await stop() };
      case 'status': return status();
      default: throw new Error(`unknown message ${message.type}`);
    }
  };
  run().then((value) => reply({ ok: true, value }), (error) => reply({ ok: false, error: error.message }));
  return true;
});
