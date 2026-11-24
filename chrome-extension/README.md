# Auth Check Recorder

A Chrome extension that records a login and writes the
[Auth Check](../README.md) identities for it: one Groovy auth script, plus an
identities file that **Auth Check → Identities → Import** reads.

You log in once in a normal browser tab. The recorder works out which requests the
session depends on and which values the server issued along the way: CSRF tokens,
flow ids, form actions, authorization codes, cookies, bearer tokens. The script it
writes pulls each of those from the response that issued it, so every run gets
fresh values. What you typed becomes `creds.*`, so the one script logs in as every
identity you add.

---

## Installing

Not on the Chrome Web Store. Each
[release](https://github.com/OmniCyber-Security/burp-auth-check/releases) attaches
`auth-check-recorder-<version>.zip` next to the Burp jar, at the same version.

1. Download the zip and unzip it somewhere it can stay. Chrome loads the extension
   from that folder every time it starts.
2. `chrome://extensions` → turn on **Developer mode**.
3. **Load unpacked** → select the unzipped folder.
4. Pin **Auth Check Recorder** to the toolbar.

To update, unzip the new release over the same folder and press the reload icon on
the extension's card. From a checkout, **Load unpacked** on `chrome-extension/`
works the same way.

Needs Chrome (or another Chromium browser) 125 or newer.

## Recording a login

1. **Use a clean profile.** A guest window or a fresh Chrome profile works. If the
   browser is already signed in, or remembers this device at the identity provider,
   the login you record is not the login a fresh client goes through. The recorder
   warns about any cookie it sees that the login did not set.
2. Open the target's login page and click the toolbar button → **Start recording**.
   By default this reloads the page, so the login page itself (with its CSRF token)
   is captured.
3. Log in as you normally would: username, password, and any MFA code.
4. Load one page that needs the session, such as a dashboard or a call to `/api/me`.
   That request becomes the **proof request**, and whatever it carries that the
   login produced is what the script returns.
5. Click **Stop and review**. The editor opens.

Chrome shows *"Auth Check Recorder started debugging this browser"* for as long as
it records. That banner is how you can tell the recorder sees everything in the tab.
Clicking **Cancel** on it stops the recording and keeps what was captured.

**Through Burp:** the recorder does not care what proxy the browser uses. Recording
through Burp's proxy puts the same traffic in Proxy history as well.

## Reviewing

The editor has the request list on the left and the output on the right.

| Area | What it is for |
|---|---|
| **Requests** | A ticked request is a step in the script. The recorder ticks the requests the session depends on: every request that carried a credential, plus anything they depend on, recursively. Untick one to drop it, or tick one it left out. **Proof** chooses the request that shows the login worked. Click a row to see the full exchange. |
| **Script** | The generated script, updated live. |
| **Credentials** | The values you typed that turned up in requests, and the `param` each one becomes. You can rename them, change their type or whether they are required, or add a value the recorder missed (for example a password-manager autofill that never fired an input event). |
| **Session** | The cookies and headers the script returns, and the origin that becomes `creds.base`. |
| **Identities** | One row per identity. Every identity shares the script and has its own credentials. Fill in a row for each user you need to test. |
| **Warnings** | Anything the script replays as a recorded literal that could go stale. |

Then **Download identities for Burp**, and in Burp go to
**Auth Check → Identities → Import**. Press **Test authentication now** on an
identity to watch the script log in; the **Login traffic** tab shows every request
it sent.

## What it handles

| Pattern | How |
|---|---|
| CSRF token in a hidden field or `<meta>` | A regex anchored on the element's `name`/`id`, checked against the recorded page so its first match is the token |
| Token in inline JSON or script | A regex on the surrounding text, widened until its first match is the value |
| JSON login → token | `http.json(resp)?.'data'?.'accessToken'` |
| Session cookies | A cookie jar in the script, kept per host so an identity provider and the app can both set a `JSESSIONID`. Each request sends exactly the cookies the browser sent |
| Redirect chains (OIDC, SAML-style hops) | Each hop requests the `Location` the server just sent, so `state`, `code` and similar values are always current |
| Form actions carrying flow ids (Keycloak, many IdPs) | The whole action URL, HTML-unescaped |
| Values in a redirect's query or fragment | `queryParam(Location, 'code')` |
| TOTP second factor | Recognised from a 6–8 digit one-time-code field. Becomes a `totpSecret` param, and the code is generated on each run |
| HTTP Basic | Rebuilt from `creds.username` and `creds.password` |
| A login that has changed | Each step checks its status class against the recording and names the step that differs. Each extraction names what it could not find |

## Limits

- **Values the page's own JavaScript generates** (PKCE verifiers, nonces, some
  `state` values) are replayed exactly as recorded. Most servers accept that, and
  the Warnings tab lists them. If yours does not, generate the value in the script.
- **SMS and email codes** cannot be scripted. Recording one gives you a step you need
  to edit.
- **Logins in a popup window** happen in a different tab and are not recorded.
  The recorder also attaches to cross-origin iframes, but that path has had less
  testing than top-level navigation.
- **Service-worker traffic** is not seen by the tab's debugger.
- **Non-ASCII text** next to an extracted value is matched as Chrome decoded it.
  If Burp decodes the response differently, the extraction fails and names the
  value it could not find. Edit the regex in the script if that happens.
- Treat the script as a first draft for anything unusual. It is meant to be read
  and edited, and it uses the same `http` helper as the bundled templates.

## Privacy

A recording holds everything the tab sent and received while recording, including
the credentials you typed and live session tokens. It is kept in the extension's
local storage, unencrypted, until you **Delete recording**. Nothing is sent
anywhere. The extension makes no network requests of its own.

The identities file holds the credentials in clear text, just like Burp's own
**Export all…**.

Permissions:

| Permission | Why |
|---|---|
| `debugger` | To read requests and responses (bodies, `Cookie`, `Set-Cookie`) in the tab you record, and nothing else |
| `activeTab` | To show the current tab's address in the popup |
| `storage`, `unlimitedStorage` | To keep recordings, which include response bodies |

## Development

No build step and no dependencies. The code is plain ES modules.

```
src/background.js     service worker: attaches the debugger, saves the capture
src/lib/recorder.js   CDP Network events → exchanges; the in-page input hook
src/lib/analyse.js    credentials, correlations, dependency closure → a plan
src/lib/groovy.js     plan → script
src/lib/identities.js plan + script → Burp's identity import format
src/editor.*          review UI
src/popup.*           start / stop
```

```bash
node --test          # unit tests and golden scripts
npm run golden       # rewrite test/golden/*.groovy after an intended change
node build.mjs       # dist/auth-check-recorder-<manifest version>.zip
node build.mjs --version 1.4.0   # what the release job runs, stamping the release version
```

`test/golden/*.groovy` is also read by the Burp extension's
`RecordedScriptsTest`. That test compiles each script against the real script
engine and runs it against a fake server that issues different tokens, cookies and
codes from the ones recorded. Run `./gradlew test` at the repository root after
regenerating them.
