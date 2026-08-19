# Auth Check — authorisation testing for Burp Suite

A Burp extension for answering "can user 1 reach user 2's data?" — and for keeping
that test honest against applications whose sessions die in minutes.

It takes a request that worked for one user, replays it as every other identity you
have configured **plus once with no credentials at all**, and tells you whether the
server enforced authorisation or handed the data over.

Built on PortSwigger's **Montoya API** (2026.7). Auth-maintenance scripts are
**Groovy**. Identities, credentials, scripts, settings, every tested request and
response, and the login traffic each script generated are all stored **in the Burp
project**, so reopening it restores the evidence as well as the setup.

---

## Contents

- [Why the session handling matters](#why-the-session-handling-matters)
- [Installing](#installing)
- [Building from source](#building-from-source)
- [CI and releases](#ci-and-releases)
- [Quick start](#quick-start)
- [Auth scripts](#auth-scripts)
- [Keeping short-lived sessions alive](#keeping-short-lived-sessions-alive)
- [Reading the verdicts](#reading-the-verdicts)
- [Avoiding false positives](#avoiding-false-positives)
- [Session-handling actions](#session-handling-actions-scanner-and-intruder)
- [What is stored in the project](#what-is-stored-in-the-project)
- [Settings reference](#settings-reference)
- [Project layout](#project-layout)
- [Testing](#testing)

---

## Why the session handling matters

An authorisation test is only as good as the session it runs with. If user 2's token
expired thirty seconds ago, every replay comes back `401` and the whole run looks
like a clean bill of health — the worst possible failure mode for this kind of tool.

The hard part is that **`401` and `403` are also the correct answer**: they are what
a properly enforced check returns. A tool that treats every denial as "session
expired, log in again" will hammer the login endpoint on every enforced result. One
that treats no denial as expiry will silently report false negatives.

This extension separates the two cases explicitly:

| Signal | How it is obtained | What happens |
|---|---|---|
| **Definitive expiry** | Your per-identity *invalid-session pattern* matched the response | Re-authenticate, replay once, use the replay's verdict |
| **Ambiguous denial** | `401`/`403` with a *session-check URL* configured | Probe that URL (answer cached 5s); only re-authenticate if it says the session is dead |
| **Ambiguous denial, no probe** | `401`/`403` with no session-check URL | One speculative re-auth per identity per 10s; if it returns the same credentials, the denial is reported as genuine enforcement |
| **Scheduled expiry** | You set a *session lifetime* | A background task re-authenticates at 80% of that age, so replays never race the expiry |

Re-authentication is serialised per identity, so ten concurrent workers needing the
same expired session cause **one** login, not ten.

---

## Installing

Grab `burp-auth-check-<version>.jar` from
[**Releases**](https://github.com/OmniCyber-Security/burp-auth-check/releases) — the
`latest` prerelease always tracks the current `main`.

Then: Burp → **Extensions** → **Installed** → **Add** → Extension type **Java** →
select the JAR. A new **Auth Check** tab appears.

## Building from source

Requires a JDK 17 or newer. The Gradle wrapper is included; nothing else to install.

```bash
./gradlew shadowJar   # -> build/libs/burp-auth-check-1.0.0.jar (~8 MB, bundles Groovy)
./gradlew test        # 60 tests
./gradlew build       # both
```

The Montoya API is `compileOnly` and is deliberately **not** bundled — Burp provides
it at runtime.

## CI and releases

`.github/workflows/build.yml` builds and tests on every push and pull request, and
publishes the jar:

| Trigger | Result |
|---|---|
| Push to any branch, or a PR | Build + test; jar kept as a build artifact for 90 days |
| Push to `main` | The above, plus the rolling **`latest`** prerelease is replaced with the new jar |
| Push a **`v*`** tag | The above, plus a permanent versioned release with generated notes |

The rolling release is deleted and recreated each time, so `main` always has a
one-click jar without accumulating a release per commit. Cut a fixed build with:

```bash
git tag v1.1.0 && git push origin v1.1.0
```

Two notes on how it is set up:

- The Gradle wrapper jar is executable code committed to the repo, so the pipeline
  validates it against Gradle's published checksums before running it.
- The organisation defaults workflow tokens to read-only. The workflow requests
  `contents: write` explicitly, which is the minimum needed to publish a release, and
  nothing else. If that org policy is ever tightened to hard-deny, the release steps
  will 403 and a PAT secret would be needed instead.

---

## Quick start

1. **Identities** tab → **Add**. Name it after the user ("User 1 — owner",
   "User 2 — other tenant", "Admin").
2. Fill in the **credential variables**. These are plain name/value pairs your
   script reads as `creds.<name>`. Values whose name looks secret are masked in the
   UI until you tick *Show values*.
3. On the **Auth script** tab, either insert a template and adapt it, or skip
   scripting entirely and just set a fixed header on the **Request rewriting** tab.
4. Press **Test authentication now**. You get the resulting auth material and the
   script's log, so you can confirm the login works *before* testing anything.
5. Repeat for each user.
6. **Browse the application as the user who owns the data** — the most privileged
   user, or the owner of the records you care about. That traffic is the baseline.
7. Either tick **Auto-test in-scope traffic** on the Results tab, or right-click any
   request anywhere in Burp → **Send to Auth Check**.

Set Burp's target scope before enabling auto-testing. Every tested request is
replayed once per identity, so a scope of "the whole internet" is both noisy and
slow.

---

## Auth scripts

Groovy. The script runs whenever a session is needed and whenever one dies. The last
expression — or an explicit `return` — is the auth material applied to every replay.

### Bindings

| Binding | What it is |
|---|---|
| `creds` | This identity's credential variables, e.g. `creds.username` |
| `http` | HTTP helper (below). Requests go through Burp, so they appear in the Logger |
| `vars` | Mutable map that **survives between refreshes** — stash refresh tokens here |
| `log` | `log.info` / `log.warn` / `log.error`, shown under the script and in Burp's output |
| `api` | The full Montoya `MontoyaApi`, for anything the helper does not cover |
| `identity` | This identity's name |

### The `http` helper

| Call | Does |
|---|---|
| `http.get(url)` / `http.get(url, headers)` | GET |
| `http.postJson(url, map)` | POST JSON; maps and lists are serialised for you |
| `http.postForm(url, map)` | POST a URL-encoded form; values are encoded |
| `http.post(url, body, contentType)` | POST anything else |
| `http.send(request)` / `http.send(request, followRedirects)` | Send a Montoya `HttpRequest` |
| `http.status(resp)` | Status code as a number |
| `http.body(resp)` | Body as a string |
| `http.json(resp)` | Parse the body into maps and lists |
| `http.cookie(resp, name)` / `http.cookies(resp)` | One / all `Set-Cookie` values |
| `http.header(resp, name)` | A response header |
| `http.extractFrom(resp, regex)` | First capture group from the body |

Redirects are **never** followed unless you ask, because the `Set-Cookie` you need is
usually on the 302 itself and following it would discard the session. Pass `true` as
the last argument of `http.send` when a flow genuinely needs the redirect followed.
The "follow redirects when replaying" setting applies only to the request under test,
not to your scripts.

### What to return

```groovy
// bearer token
return [headers: ['Authorization': "Bearer $token"]]

// session cookie
return [cookies: ['JSESSIONID': session]]

// a bare string goes into the identity's configured token header
return "Bearer $token"

// a bare map with no recognised wrapper key is treated as HEADERS
return ['X-Api-Key': creds.token]

// everything at once
return [
    headers: ['Authorization': "Bearer $token", 'X-Tenant': creds.tenant],
    cookies: ['csrf': csrfCookie],
    params : [[type: 'BODY', name: '_csrf', value: csrf]],
    remove : ['If-None-Match']
]
```

> **Cookies must be wrapped in `cookies:`.** A bare map is applied as *headers*,
> which is the same shape `http.cookies(resp)` returns — so `return http.cookies(resp)`
> quietly sets a header called `JSESSIONID` and your replays go out with no cookie at
> all. Write `return [cookies: http.cookies(resp)]`. The script log warns when a bare
> map is applied as headers, and the identity's **Login traffic** tab shows what
> actually went on the wire.

`params` accepts the Montoya types: `URL`, `BODY`, `COOKIE`, `JSON`, `XML`,
`XML_ATTRIBUTE`, `MULTIPART_ATTRIBUTE`. A parameter already on the request is
updated; one that is not is added.

**Throw an exception to signal failure.** The message lands on the identity's status
line and the affected rows read **Auth failed** — rather than replaying without
credentials and manufacturing a bypass. A script that returns nothing usable and has
no static headers is treated as a failure for the same reason.

Worked examples are in [`scripts/`](scripts/):

| File | Pattern |
|---|---|
| `json-login-bearer.groovy` | JSON login → bearer token |
| `form-login-session-cookie.groovy` | HTML form login with CSRF → session cookie |
| `oauth2-refresh-token.groovy` | Password grant, reusing the refresh token via `vars` |
| `csrf-token-per-request.groovy` | Session cookie plus a CSRF token in the body |

Everything a script sends is recorded and shown on the identity's **Login traffic**
tab — the exact requests and responses of the last login, kept in the project. It is
the fastest way to see why a login is failing, and it is what makes a finding
reproducible later.

Scripts run with a timeout (default 30s) so a hung login endpoint cannot wedge the
worker threads.

---

## Keeping short-lived sessions alive

Per identity, on the **Session lifetime** tab:

- **Session lifetime (seconds)** — if the app expires sessions on a timer, state it.
  Background re-auth happens at 80% of that age. `0` disables the timer.
- **Invalid-session pattern** — a regex matched against the replayed response's
  status line, headers and body. This is the reliable signal; on a match the session
  is rebuilt and the request replayed once. Good values:
  `(?i)"error"\s*:\s*"(invalid_token|token_expired)"`, `(?i)please log in again`.
- **Session-check URL** + **Healthy-session pattern** — a cheap authenticated
  endpoint used to settle whether a `401`/`403` meant "expired" or "not allowed".
  Leave the pattern empty to accept any 2xx/3xx.

Configuring the invalid-session pattern is the single highest-value thing you can do
for a fast-expiring target. Without it the extension falls back to rate-limited
guessing, which is safe but slower to react.

---

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| **Bypassed** | Same status and near-identical body as the baseline: this identity reached the resource. Your finding. |
| **Enforced** | The server refused — denied status code, denial pattern in the body, or a redirect to login. |
| **Review** | Different from the baseline but not a recognisable denial. Usually the identity's own data; sometimes a partial leak. Read it. |
| **Auth failed** | No session could be established, so nothing was proven. Fix the script first. |
| **Error** | The replay itself failed — connection refused, timeout. |

Select a row to get every variant's full request and response side by side, plus the
reasoning behind the verdict. Sorting a verdict column puts the worst first. Hovering
a verdict cell shows the explanation. **Findings only** hides everything but bypasses.
**Export CSV** writes every verdict with its explanation.

---

## Avoiding false positives

Two situations make a naive tool cry wolf, and both are handled explicitly:

**A public endpoint.** If the unauthenticated replay also succeeds, then every
identity "bypassing" it is expected. Those rows are annotated *endpoint appears
public*, and the Unauthenticated column makes it obvious at a glance — which is the
main reason to leave that replay switched on.

**A baseline that was not a success.** Comparing against a `404` or a `500` proves
nothing. Rather than claim a bypass because two `404`s match, those rows degrade to
**Review** and say why.

Body comparison uses a Sørensen–Dice coefficient over character shingles. Whitespace
is collapsed and high-entropy token-like runs (16+ characters mixing letters and
digits — CSRF tokens, session ids, JWT segments) are masked, so per-session noise
does not hide a real bypass. Nothing else is normalised: names, amounts, dates and
short ids are exactly what distinguishes "the other user's record" from "the same
record", and masking those would invent bypasses. Tune the threshold in Settings, or
switch to Burp's own response-variations analyser.

---

## Session-handling actions (Scanner and Intruder)

Each identity is also published as a Burp session-handling action named
**"Auth Check: authenticate as &lt;identity&gt;"**.

Burp → Settings → **Sessions** → Session handling rules → Add → Rule actions → Invoke
a Burp extension → pick the action. Now Scanner, Intruder and Repeater traffic gets
that identity's live credentials, with the same automatic re-authentication. This is
what makes a long scan survive a five-minute session timeout.

---

## What is stored in the project

Everything lives in the **Burp project file** via `api.persistence().extensionData()`.
Reopen the project and the whole engagement comes back — configuration *and* evidence.

| Stored | Detail |
|---|---|
| Identities and credential variables | The `creds` values each script reads |
| Auth scripts | Verbatim, per identity |
| Settings | Filters, thresholds, denial rules |
| **Tested requests and responses** | The baseline exchange plus every identity's replay, with its verdict, explanation, similarity score and re-auth flag |
| **Login traffic** | Every request an auth script sent while logging in, and what came back — stored against the identity, next to the script that produced it |

That combination is deliberate: months later a disputed finding can be reconstructed
from the project alone — the script, the credentials it read, the login exchange that
minted the session, the replay that used it, and the baseline it was judged against.

Restored results keep their original numbering and timestamps, and new results carry
on from the highest number restored.

### Controlling the size

Each stored result holds the baseline exchange plus one per identity, so storage is
the main thing the extension adds to a project file. Under **Settings → Storing
results in the project**:

- **Store tested requests and responses** — off writes nothing (default on).
- **Store only rows worth revisiting** — keeps bypassed, review and auth-failed rows
  and discards the enforced ones, which are usually the bulk.
- **Store at most N results** — default 500, independent of how many are held in
  memory. Oldest are dropped first. `0` stores none.

Login traffic is one flow per identity, replaced on each login, so it stays small.
**Clear** on the Results tab wipes stored results too; login traffic is kept with the
scripts until you delete the identity.

Writes happen on a dedicated thread and are shed if they fall behind, so storage never
throttles testing.

> **Nothing here is encrypted.** Burp does not encrypt extension data, and the project
> now holds credentials, live session tokens in the stored login traffic, and response
> bodies from the application. Treat the project file as sensitive material, and prefer
> dedicated test accounts.

---

## Settings reference

**What gets tested** — auto-test on/off; test unauthenticated; restrict to Burp
scope; which tools' traffic to watch (Proxy and Repeater by default); dedupe by
endpoint; skip static resources; skip baseline status codes; URL include/exclude
regexes.

Requests sent by extensions are **never** auto-tested, regardless of settings —
otherwise the extension would test its own replays forever. "Send to Auth Check"
ignores every filter, including dedupe.

**Judging responses** — same-response threshold (default 95%); comparison byte cap;
Burp variations analyser instead of similarity; follow redirects on replay (off by
default, so a 302 to `/login` reads as enforcement).

**What counts as denied** — status codes (401, 403); a body regex; whether a redirect
to a login URL counts, and the login URL pattern.

**Unauthenticated replay** — which headers to strip.

**Storing results in the project** — whether to store tested requests and responses,
whether to limit that to rows worth revisiting, and the storage cap.

**Performance** — worker threads; queue capacity; response timeout; script timeout;
result cap. When the queue is full, work is shed and the count is shown in the status
line rather than growing memory or blocking Burp's proxy threads.

---

## Project layout

```
.github/workflows/build.yml      Build, test, publish releases
src/main/java/com/omnicybersecurity/authcheck/
├── AuthCheckExtension.java      Entry point; wires everything and registers hooks
├── model/                       Identity, AuthMaterial, verdicts, test records
├── config/                      Settings, live state, Burp-project persistence
├── auth/                        Groovy engine, script API, session lifecycle
├── engine/                      Request rewriting, response analysis, orchestration
├── integration/                 Traffic handler, context menu, session actions
└── ui/                          Suite tab: results, identities, settings, help
```

The **Help** tab inside the extension carries the same script reference, so you do
not need this file open while testing.

## Testing

60 JUnit tests cover the parts that decide whether you have a finding, and the parts
that decide whether you still have it tomorrow:

- **Verdicts** — bypass/enforced/review rules, denial detection, unsuccessful baselines.
- **Similarity** — the Dice metric and its token masking, in both directions: session
  noise must not hide a bypass, and one user's data must not masquerade as another's.
- **Request rewriting** — strip order, cookie merging, static-header precedence.
- **The Groovy engine**, end to end — credentials, `vars` persistence, JSON parsing,
  failure reporting, timeouts.
- **Project persistence**, round-tripped — identities, credentials, scripts, tested
  requests and responses, verdicts, and login traffic, plus the storage cap, the
  filters, and coexistence of results with configuration.

Montoya's static factories and its object factory only exist inside Burp, so the tests
install their own factory (`support/FakePersistence.java`) and drive the real
`ConfigStore` and `ResultsRepository` code. The API does not state whether a child
object fetched from the project is a live view or a copy, so every persistence test
runs against **both** semantics and the extension probes which one it has at startup.

```bash
./gradlew test
```

```bash
./gradlew test
```
