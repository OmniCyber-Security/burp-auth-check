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
- [BApp Store submission](#bapp-store-submission)
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
[**Releases**](https://github.com/OmniCyber-Security/burp-auth-check/releases). Every
merge that changes the jar publishes one, so the newest release is the current `main`.

Then: Burp → **Extensions** → **Installed** → **Add** → Extension type **Java** →
select the JAR. A new **Auth Check** tab appears.

## Building from source

Requires a JDK 17 or newer. The Gradle wrapper is included; nothing else to install.

```bash
./gradlew shadowJar   # -> build/libs/burp-auth-check-<version>.jar (~8 MB, bundles Groovy)
./gradlew test        # 145 tests
./gradlew build       # both
```

The Montoya API is `compileOnly` and is deliberately **not** bundled — Burp provides
it at runtime.

## CI and releases

`.github/workflows/build.yml` builds and tests every push and pull request, and
publishes a release when `main` moves. `.github/workflows/release-label.yml` is the
status check that makes the release decision possible.

### The version comes from a label

Every pull request carries exactly one release label. The **release label** check
fails until it does, so the question is answered before the merge rather than after:

| Label | Effect on the newest `vX.Y.Z` tag |
|---|---|
| `release:major` | `X+1.0.0` — incompatible change to how the extension is used or configured |
| `release:minor` | `X.Y+1.0` — new capability, backwards compatible |
| `release:patch` | `X.Y.Z+1` — fix or internal change, no new capability |
| `release:none` | No release. Docs, CI, and anything that does not change the jar |

On a push to `main` the release job reads that label off the merged pull request,
works out the next version from the newest `v*` tag, builds the jar **stamped with
that version**, then creates the tag and the release and attaches the jar. A commit
pushed straight to `main` has no pull request and so releases nothing; run the
workflow manually with a `bump` input if it should have.

The tags are the source of truth for the version. `version` in `gradle.properties`
is only the fallback for local builds — CI overrides it with `-Pversion=<next>`, which
is what keeps the jar's `Implementation-Version` honest.

### How it is set up

- **Every action is pinned to a commit SHA**, with the tag it corresponded to in a
  trailing comment. A moved tag cannot change what runs.
- **The logic is `actions/github-script`**, not third-party actions — including the
  Gradle wrapper check, which fetches the checksum Gradle publishes for the exact
  distribution `gradle-wrapper.properties` names and compares it against the
  committed jar. The wrapper is executable code in the repository that runs before
  anything else, so it is checked before anything else.
- **Pull requests cannot reach a write token.** The workflow is `contents: read` by
  default; only the release job widens that, and it is gated on `push` to `main` or a
  manual run. Neither is reachable from a `pull_request` event, and nothing uses
  `pull_request_target`. The label check runs with `permissions: {}` and never checks
  out the branch — it reads labels from the event payload, which only maintainers can
  set.
- **No untrusted value is interpolated into a shell.** Values computed by the
  workflow reach `run:` steps through `env:`, and everything else stays inside
  `github-script`, where the event payload is data rather than script.
- The organisation defaults workflow tokens to read-only. The release job requests
  `contents: write` for the tag, the release and its asset, and `pull-requests: read`
  to read the label off the merged pull request — a job-level block replaces the
  workflow default outright rather than adding to it, so both have to be listed. If
  that org policy is ever tightened to hard-deny, the release steps will 403 and a
  PAT secret would be needed instead.

---

## Quick start

1. **Identities** tab → **Add**. Name it after the user ("User 1 — owner",
   "User 2 — other tenant", "Admin").
2. On the **Auth script** tab, either insert a template and adapt it, or skip
   scripting entirely and just set a fixed header on the **Request rewriting** tab.
3. Fill in the **Credentials** tab. A script that declares its credentials with a
   [`params` block](#declaring-the-credentials-a-script-needs) gives you a form with
   its own labelled fields, masked secrets and required-field checks; every template
   does. A script that declares nothing gives you a free-form name/value table, whose
   entries the script reads as `creds.<name>`.
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

### Declaring the credentials a script needs

A `params` block at the top of a script says which credential variables it reads.
The **Credentials** tab then renders exactly those fields, and the run is refused
with a precise message when a required one is empty — instead of the tester
guessing names out of a comment and finding out when the script throws.

```groovy
params {
    param 'base',     type: URL,    required: true, label: 'Base URL'
    param 'username', type: STRING, required: true
    param 'password', type: SECRET, required: true
    param 'totpSecret', type: SECRET,
          help: 'Base32 secret from the enrolment QR code. Set it if the account has MFA'
    param 'scope',    type: STRING, default: 'openid profile offline_access'
}
```

| Option | Meaning |
|---|---|
| `type:` | `STRING`, `SECRET` (masked), `INT`, `BOOL`, `URL`, `CHOICE` (with `choices: [...]`), `TEXT` (multi-line). Defaults to `STRING` |
| `required:` | `true` blocks the run while the field is empty, naming it. **Params are optional unless they say otherwise** |
| `default:` | Filled in when the field is left empty, so the script just reads `creds.scope`. A default makes a param optional, so it cannot be combined with `required: true` |
| `label:` | What the field is called in the form; the name when absent |
| `help:` | One line under the field explaining when to set it |

`SECRET` matters beyond the widget: without a declaration, masking is guessed from
the name, so a key called `enrolment_code` is shown in the clear. Declaring it says
so outright.

Three things worth knowing:

- **Declaring is optional.** A script with no `params` block gets the free-form
  table it always had. Nothing written before this existed needs changing.
- **Nothing is ever lost.** A credential the script does not declare stays in the
  table under the form — including one that *was* declared until you edited the
  script. Editing a script never destroys a value you typed.
- **The block is read without running the script**, straight from the source, which
  is why every value in it has to be a literal. A name built at runtime is rejected
  rather than guessed at.

The same checks run wherever authentication is triggered from, so a run started by a
session-handling rule fails with the same message as one started from the UI.

### Bindings

| Binding | What it is |
|---|---|
| `creds` | This identity's credential variables, e.g. `creds.username` — declare them with `params` (below) |
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
| `api-key-header.groovy` | Static API key or token — no login flow |
| `json-login-bearer.groovy` | JSON login → bearer token |
| `form-login-session-cookie.groovy` | HTML form login with CSRF → session cookie |
| `oauth2-refresh-token.groovy` | Password grant, reusing the refresh token via `vars` |
| `csrf-token-per-request.groovy` | Session cookie plus a CSRF token in the body |
| `login-then-assume-role.groovy` | Two-step: log in, then elevate to a role |
| `totp-mfa-login.groovy` | Login behind a TOTP second factor, code generated |
| `_api-reference.groovy` | Every binding and helper, with types. Not a template |

Those files **are** the templates in the extension's *Insert template* menu — the
build copies them into the jar, so there is no second copy to keep in step. Drop a
new `.groovy` in `scripts/` and it appears in the menu after a rebuild; its first
line of comment prose becomes the entry. A test compiles every one of them, so a
broken example fails the build instead of reaching a tester.

Scripts are compiled against `AuthScriptBase`, which declares `creds`, `http`,
`vars`, `log`, `api` and `identity` with real types. Put the jar on an IDE's
classpath and those complete and type-check while you write.
[`scripts/README.md`](scripts/README.md) has the setup, and
[`scripts/_api-reference.groovy`](scripts/_api-reference.groovy) is the whole surface
in one file.

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
reasoning behind the verdict. Sorting a verdict column puts the worst first, and the
sort you choose is remembered in the project — it is stored against the column's
identity rather than its position, so adding or removing an identity does not leave
you sorted by the wrong column. Hovering
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

> **The extension name addresses this storage.** Burp identifies persisted extension
> data by the extension's name, so the name is a fixed constant and must stay that
> way — putting a version or build id in it gives every build its own storage and
> makes an update look exactly like losing every identity. Builds 380dc8a–197f9dc did
> this; 1.1.1 migrates anything they stranded back automatically on first load.
>
> Use **Identities → Export all…** for a backup that does not depend on any of this.
> It is also how an identity set moves between projects or testers. The file holds
> credentials in clear text.

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
endpoint; skip static resources; skip baseline status codes; **skip HTTP methods**;
URL include/exclude regexes.

Filtered methods never reach the results at all. `OPTIONS` is skipped by default: a
CORS preflight carries no authorisation decision, and testing one per request would
triple the traffic for nothing. Clear the list to test every method.

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

---

## BApp Store submission

Submission text, and where the extension stands against PortSwigger's
[acceptance criteria](https://portswigger.net/burp/documentation/desktop/extensions/creating/bapp-store-acceptance-criteria).

- **Name:** Auth Check — authorisation testing
- **Summary:** Replays each request as every configured identity and unauthenticated,
  keeping short-lived sessions alive with scripted logins.

### How it differs from the existing authorisation BApps

Autorize and Auth Analyzer both replay a request as a second user. This extension
differs in what it does about the session underneath that replay, which is the part
that decides whether a run is trustworthy:

- **Any number of identities per run**, plus a mandatory unauthenticated variant, in
  one record — rather than one "low-privilege user" at a time.
- **Sessions are scripted, not captured.** An identity owns a Groovy login script,
  so credentials that expire in minutes (OIDC, TOTP, refresh tokens, assumed roles)
  are re-obtained rather than pasted in again.
- **Expiry is distinguished from enforcement.** A `401` is both the correct answer to
  an authorisation check and the symptom of a dead session; the two are separated by
  an explicit liveness probe rather than guessed at. See
  [Why the session handling matters](#why-the-session-handling-matters).
- **The evidence is in the project.** Baseline, every replay, and the login traffic
  each script generated reopen with the project file.
- **The login scripts are reusable outside this extension** as Burp
  session-handling actions, so Scanner and Intruder get the same live sessions.

### Criteria

| Criterion | How it is met |
|---|---|
| Unique function | See above. |
| Clear, descriptive name | "Auth Check — authorisation testing", with the summary above. |
| Operates securely | Response content is treated as data throughout: it is never rendered as HTML (the one tooltip built from it is escaped), never deserialised, and never used to build a request except through the tester's own script. The only code the extension executes is Groovy the tester wrote or imported, and importing a shared identity file warns that it carries executable scripts before adding it. Credentials live unencrypted in the Burp project — stated in the UI, in the export file, and in [What is stored in the project](#what-is-stored-in-the-project). |
| Includes all dependencies | Groovy is shaded into the jar. Montoya is `compileOnly`; Burp provides it. |
| Uses threads | No slow work on the event thread or Burp's: replays, logins, script compilation, persistence and file export all run on the extension's own pools. Every task body is wrapped in try/catch that writes to the extension error stream, because Burp does not report what escapes a background thread. |
| Unloads cleanly | `registerUnloadingHandler` saves configuration, stops all four executors, deregisters the per-identity session-handling actions, closes the Groovy classloader, and flushes pending project writes before returning. All threads are daemons as a backstop. |
| Uses Burp networking | Every request — replays, liveness probes and everything an auth script sends through the `http` binding — goes through `api.http().sendRequest()`, so upstream proxies and session-handling rules are obeyed and the traffic appears in Logger. |
| Supports offline working | No online services are contacted. The script templates are bundled in the jar. |
| Copes with large projects | Nothing passed to `HttpHandler` is retained: messages are copied with `copyToTempFile()` before queueing, and every stored exchange stays on disk rather than in heap. The site map and Proxy history are never enumerated. Both the in-memory and the persisted result counts are capped. |
| Parents GUI elements | Every dialog and file chooser is parented via `swingUtils().windowForComponent()`, falling back to `swingUtils().suiteFrame()`. |
| Uses the Montoya API artifact | `net.portswigger.burp.extensions:montoya-api`, via Gradle. |
| Burp AI as default provider | No AI functionality. |

---

## Testing

145 JUnit tests cover the parts that decide whether you have a finding, and the parts
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
