// Captures in chrome.storage.local: one key per capture plus a small index,
// so listing them never loads every response body.
//
// Nothing here is encrypted. A capture holds the tester's credentials and
// live session tokens, which is why the editor offers to delete it.

const INDEX = 'captures';
const key = (id) => `capture:${id}`;

export async function listCaptures() {
  const { [INDEX]: index = [] } = await chrome.storage.local.get(INDEX);
  return index.sort((a, b) => b.startedAt - a.startedAt);
}

export async function loadCapture(id) {
  const { [key(id)]: capture } = await chrome.storage.local.get(key(id));
  return capture || null;
}

export async function saveCapture(capture) {
  const { [INDEX]: index = [] } = await chrome.storage.local.get(INDEX);
  const entry = {
    id: capture.id,
    title: capture.title,
    tabUrl: capture.tabUrl,
    startedAt: capture.startedAt,
    requests: capture.exchanges?.length ?? 0,
  };
  await chrome.storage.local.set({
    [key(capture.id)]: capture,
    [INDEX]: [...index.filter((c) => c.id !== capture.id), entry],
  });
}

export async function deleteCapture(id) {
  const { [INDEX]: index = [] } = await chrome.storage.local.get(INDEX);
  await chrome.storage.local.remove(key(id));
  await chrome.storage.local.set({ [INDEX]: index.filter((c) => c.id !== id) });
}
