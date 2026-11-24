const $ = (id) => document.getElementById(id);

async function call(type, extra = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...extra });
  if (!response?.ok) throw new Error(response?.error || 'No response from the recorder');
  return response.value;
}

let tab;
let timer;

async function refresh() {
  const status = await call('status');
  const recordingHere = status.recording && status.tabId === tab.id;
  $('idle').hidden = status.recording;
  $('recording').hidden = !status.recording;
  if (status.recording) {
    $('count').textContent = status.requests;
    $('inputs').textContent = recordingHere
      ? `${status.inputs} field value${status.inputs === 1 ? '' : 's'} captured`
      : `Recording another tab: ${status.title}`;
  }
}

async function guard(action) {
  $('error').textContent = '';
  try {
    await action();
  } catch (error) {
    $('error').textContent = error.message;
  }
}

$('start').addEventListener('click', () => guard(async () => {
  await call('start', { tabId: tab.id, options: { reload: $('reload').checked, clearCookies: $('clear').checked } });
  await refresh();
}));

$('stop').addEventListener('click', () => guard(async () => {
  await call('stop');
  window.close();
}));

$('editor').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('src/editor.html') });
  window.close();
});

guard(async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  $('target').textContent = tab?.url || '';
  await refresh();
  timer = setInterval(() => refresh().catch(() => clearInterval(timer)), 700);
});
