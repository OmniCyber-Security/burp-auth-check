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
- [User guide: testing a web application](#user-guide-testing-a-web-application)
- [Auth scripts](#auth-scripts)
- [Recording a login in Chrome](#recording-a-login-in-chrome)
- [Keeping short-lived sessions alive](#keeping-short-lived-sessions-alive)
- [Reading the verdicts](#reading-the-verdicts)
- [Avoiding false positives](#avoiding-false-positives)
- [Session-handling actions](#session-handling-actions-scanner-and-intruder)
- [Several apps in one project](#several-apps-in-one-project)
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
| **Ambiguous denial** | An **Enforced** replay (denied status, denial pattern or login redirect) with a *session-check URL* configured | Probe that URL (answer cached 5s); only re-authenticate if it says the session is dead |
| **Ambiguous denial, no probe** | An **Enforced** replay with no session-check URL | One speculative re-auth per identity per 10s; if it returns the same credentials, the denial is reported as genuine enforcement |
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
./gradlew test        # 152 tests
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
| `release:none` | No release. Docs, CI, and anything that changes neither the jar nor the Chrome recorder |

On a push to `main` the release job reads that label off the merged pull request,
works out the next version from the newest `v*` tag, builds the jar **stamped with
that version**, then creates the tag and the release and attaches the jar. The
[Chrome recorder](#recording-a-login-in-chrome) is packaged in the same job, with the
same version stamped into its manifest, and attached beside it as
`auth-check-recorder-<version>.zip`. A commit
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
   request anywhere in Burp → **Send to Auth Check**. Restricting auto-test to Burp's
   scope is the separate **Only test URLs in Burp's target scope** setting, on by
   default.

Set Burp's target scope before enabling auto-testing. Every tested request is
replayed once per identity, so a scope of "the whole internet" is both noisy and
slow.

---

## User guide: testing a web application

The [Quick start](#quick-start) is the short version. This is the long one: an
authorisation test from first contact with the client to the report, in the order
you will do it. Each step links to the reference section that has the detail.

### 1. Before you start

Ask the client for accounts before the test window opens. Authorisation testing
is only as good as the users you have:

- **At least two users in every role**, and in every tenant if the application is
  multi-tenant. Two users with the same role are what horizontal checks (user A
  reading user B's records) need. One user per role only gives you vertical checks.
- **An administrator**, or the most privileged role the application has. Their
  traffic is the reference for "what access looks like" on admin functions.
- **Dedicated test accounts**, not real staff accounts. Credentials and live
  session tokens end up in the Burp project file, unencrypted.
- **MFA details**, if the accounts use it. For TOTP, ask for the base32 secret
  from enrolment (or enrol the account yourself and keep the secret). SMS and email
  codes cannot be scripted.

Agree two things in writing:

- **How to treat state-changing requests.** Every tested request is sent again
  verbatim, method and body included, once with no credentials and once per
  identity. A `POST`, `PUT`, `PATCH` or `DELETE` you make while browsing is
  therefore repeated `1 + N` times, and an identity that re-authenticates mid-test
  can send it twice. Nothing in the extension treats those methods differently
  unless you configure it to (step 4). On production, or with data that cannot be
  reset, agree that destructive requests are tested by hand only.
- **That the Burp project file is sensitive.** It holds every identity's
  credentials, every auth script, the login traffic with live tokens, and every
  tested response. See [What is stored in the project](#what-is-stored-in-the-project).

### 2. Install the Burp extension and the Chrome recorder

1. Install the jar as in [Installing](#installing). A new **Auth Check** tab
   appears with four sub-tabs: **Results**, **Identities**, **Settings** and
   **Help**.
2. Optional, but worth it for any login that is more than a single form post:
   install the Chrome recorder from the same release. Unzip
   `auth-check-recorder-<version>.zip` somewhere it can stay,
   `chrome://extensions` → **Developer mode** → **Load unpacked** → the unzipped
   folder, and pin **Auth Check Recorder** to the toolbar. It needs Chrome 125 or
   newer. [`chrome-extension/README.md`](chrome-extension/README.md) has the
   details.
3. Start a **new Burp project file** for the engagement. Settings and identities
   are stored per project, so a fresh project starts from the defaults.

### 3. Set Burp's target scope

Auto-testing only looks at in-scope URLs by default (**Only test URLs in Burp's
target scope**). With no scope set, nothing is tested, and the only sign of it is
a growing "skipped by filters" count on the Results status line.

Add the application's hosts to Burp's target scope, and nothing else. Leave the
identity provider out (for example `login.microsoftonline.com`) unless it is part
of the test. Auth scripts still log in there; scope only decides which captured
traffic gets replayed.

### 4. Configure Settings for the engagement

Open **Auth Check → Settings**. Nothing on this tab takes effect until you press
**Apply**. **Revert** throws away edits you have not applied, and **Restore
defaults** resets every setting (after a confirmation, and without needing
Apply) but leaves identities alone. A number that does not parse keeps its
previous value, and one out of range is clamped. Check the form after Apply.

A starting configuration for a typical web application or API:

| Setting | Default | Start the engagement with | Why |
|---|---|---|---|
| **Automatically test traffic as it arrives** | Off | Off, until every identity passes **Test authentication now** | Replays with a broken identity only produce **Auth failed** rows. The **Auto-test in-scope traffic** checkbox on the Results tab is the same setting |
| **Also replay every request with no credentials** | On | On | It is what flags public endpoints, see [Avoiding false positives](#avoiding-false-positives) |
| **Only test URLs in Burp's target scope** | On | On | The Results checkbox says "in-scope", but this is the setting that enforces it |
| **Test traffic from:** | Proxy, Repeater | **Proxy** only | With Repeater ticked, every request you send in Repeater is replayed as every identity, including the destructive ones you are probing by hand. Use **Send to Auth Check** for Repeater requests you do want tested |
| **Test each endpoint only once** | On | On | An endpoint is method, host, port and path. Query values and the scheme are not part of it |
| **Treat a different set of parameter names as a different endpoint** | On | On. Turn off if the same endpoint keeps reappearing | Parameter names include cookie names, so an app that adds cookies as you browse makes the same endpoint look new |
| **Skip these HTTP methods:** | `OPTIONS` | `OPTIONS` on a test environment you can reset. `OPTIONS, DELETE` or `OPTIONS, POST, PUT, PATCH, DELETE` where state changes were not agreed | Filtered methods are never auto-tested. You can still test one deliberately with **Send to Auth Check** |
| **Never URLs matching (regex):** | empty | `(?i)/(logout\|log-out\|signout\|sign-out)` plus any endpoint the client named as off limits | A replayed logout ends that identity's session, and the next replays then spend time re-authenticating |
| **Only URLs matching (regex):** | empty | Empty, unless the Burp scope is wider than this test | Searched anywhere in the full URL, scheme and query included. Case-sensitive unless you add `(?i)` |
| **Denied status codes:** | `401, 403` | Add whatever the application uses to refuse, for example `404` if it hides other users' records behind a not-found | A code on this list makes the replay **Enforced** |
| **Denied body pattern (regex):** | words such as `forbidden`, `unauthorized`, `access denied` | Narrow it to the application's actual denial message | It is checked against the replay at any status, before the baseline is looked at. A normal page that contains "forbidden" or "unauthorized" anywhere in its first 256 KB, such as help text or a JS bundle, reads as **Enforced**, which hides a real bypass |
| **Login URL pattern (regex):** | `/login`, `/signin`, `/auth/` and similar | Add the application's or identity provider's login path. The field replaces the default rather than adding to it, so keep the default's alternatives, for example `(?i)(/login\|/signin\|/sign-in\|/auth/\|/account/login\|/session/new\|login\.microsoftonline\.com)` | A redirect whose `Location` matches counts as **Enforced** |
| **Same-response threshold (%):** | 95 | 95 | Lower it a few points if pages carry per-request content (timestamps, short ids) that keeps true bypasses in **Review** |
| **Follow redirects when replaying** | Off | Off | A 302 to the login page stays visible as enforcement |
| **Worker threads:** | 4 | 1 or 2 for a fragile target or a production system | There is no rate limit or delay between requests. Fewer threads is the throttle. It applies to auto-testing and to **Send to Auth Check** and **Retest selected** alike, and takes effect on **Apply**: tests already running finish, and queued ones wait for a free thread |
| **Response timeout (ms):** | 20000 | Raise it for a slow target | Also applies to auth-script requests |
| **Store only rows worth revisiting (bypassed, review, auth failed)** | Off | On for a long engagement | Keeps the project file small. **Enforced** and **Error** rows are discarded |

To find the application's denial signals, log in as a low-privilege user, request
something only an administrator can see, and read what comes back: the status
code, the body, and where a redirect points. That response is what the three
denial settings should recognise. Check the reverse too: open a few ordinary pages
as an authorised user and make sure the denied body pattern does not match them.

[Settings reference](#settings-reference) lists every setting and its default.

### 5. Create the identities

Create one identity per test account, on **Auth Check → Identities**. The baseline
user does not need to be one (see step 7). Pick whichever of the three paths below
fits the login.

**Path A: record the login with the Chrome recorder.** Best for multi-hop logins
such as OIDC, SAML-style redirects, CSRF-protected forms and TOTP.

1. Open a **separate Chrome profile** and load the recorder into it (**Load
   unpacked** again in that profile; extensions do not run in a guest window). A
   browser that is already signed in, or that the identity provider remembers, does
   not go through the login a fresh client does. Alternatively tick **Delete this
   site's cookies first** in the recorder popup. It clears cookies only for the
   current page's URL, so for a login through a separate identity provider use a
   clean profile.
2. Keep auto-test off in Burp while you record, if the browser goes through Burp.
3. Open the application's login page, click the **Auth Check Recorder** toolbar
   button, and leave **Reload the page when recording starts** ticked so the login
   page and its CSRF token are captured. Press **Start recording**.
4. Log in as one of the test users: username, password and any code.
5. Load one page that needs the session, such as the dashboard or `/api/me`. The
   recorder picks the **proof request** automatically, usually the first
   successful request after login, which may not be the page you loaded.
6. Press **Stop and review**. The editor opens on the recording.
7. Check the **Requests** list (ticked requests are script steps, the **Proof**
   column marks the proof request; if the pick is wrong, select the page you
   loaded there, because it also becomes the imported session-check URL), the
   **Credentials** tab (what you typed and the param each value becomes; add
   anything missed under **Missed one?**), and the **Warnings** tab.
8. On the **Identities** tab, the first row, **Recorded user**, is pre-filled with
   what you typed. Press **Add identity** for every other account and fill in its
   row. Name each row after the user and role ("User A (tenant 1)", "Admin"). For
   TOTP, paste each account's base32 secret into its row: the code is generated on
   each run, but the secret is never captured.
9. On the **Script** tab, press **Download identities for Burp**. You get
   `auth-check-<host>-identities.json`.
10. In Burp: **Auth Check → Identities → Import...** and pick the file. The
    confirmation warns that the identities carry auth scripts, which run as Groovy
    inside Burp. Read the script on the **Auth script** tab.
11. For each identity, press **Test authentication now** on the **Auth script**
    tab, and read the result under **Last authentication**. The **Login traffic**
    tab then shows every request the script sent and what came back.
12. Delete the recording in Chrome once the identities work (**Delete
    recording**). It holds the passwords and live session tokens you used.

Import always adds identities. Importing the same file twice gives you two of
each, with the same names, so remove the extras with **Remove**.

**Path B: start from a template or write the script.** Best when the login is a
simple form or JSON call, or you already know the flow.

1. **Add**. The new identity is called "User N". Rename it on the **Credentials**
   tab (**Name:**).
2. On the **Auth script** tab, choose a template from **Insert template...**, for
   example "JSON login -> bearer token" or "HTML form login -> session cookie", and
   adapt it. [Auth scripts](#auth-scripts) is the reference.
3. Press **Check syntax**, then fill in the **Credentials** tab. Templates declare
   their fields, so you get a form with required fields marked `*`.
4. Press **Test authentication now** and check **Login traffic**.
5. For the next user of the same application, select the identity, press
   **Duplicate**, rename the copy and change its credentials. The script, session
   settings and request rewriting are copied with it.

**Path C: a static header or cookie.** For an API key, or a session you can only
obtain by hand. Put it under **Request rewriting → Always set these headers:**, one
`Name: value` per line, for example `Authorization: Bearer eyJ...` or
`Cookie: session=...`. There is no login, so nothing re-authenticates when the
token expires. The "Static API key or token in a header" and "Static session cookie"
templates do the same thing as a script. An identity with neither a script nor a
static header still "authenticates", with nothing, so its replays are just more
unauthenticated requests labelled with its name.

**Every identity, whichever path:**

- **Only URLs matching:** on the **Credentials** tab fences the identity to one
  application. Set it whenever the project covers more than one application with
  its own users. Identities imported from a recorder download have it empty, so they apply
  everywhere. Identities imported from an **Export all...** file keep the scope they
  were exported with. See
  [Several apps in one project](#several-apps-in-one-project).
- **Include this identity in tests** switches an identity off without deleting it.
  A disabled identity gets no column in the results.
- **Request rewriting → Strip these headers first:** removes the captured
  request's credentials before the identity's are applied. The default does not
  strip `Proxy-Authorization`, `Api-Key`, `X-Access-Token` or `X-Session-Token`. If
  the application authenticates with one of those, add it, or the baseline user's
  credential rides along on every replay and every row reads **Bypassed!**. Tokens
  in the query string or body are not stripped either; override them from the
  script with `params`.
- There is no Save button. Edits are saved to the project a moment after you stop
  typing.

### 6. Make the sessions survive

A test that runs for hours needs sessions that outlive it. Set these per identity
on the **Session lifetime** tab, which [Keeping short-lived sessions
alive](#keeping-short-lived-sessions-alive) describes in full. Finding the right
values for the target:

- **Session lifetime (seconds, 0 = no timer):** read it off a login. The token
  response's `expires_in`, a JWT's `exp` minus `iat`, or the session cookie's
  `Max-Age` give it directly; the identity's **Login traffic** tab has all three.
  Enter the real lifetime: the extension re-runs the script at 80% of it. This
  keeps logging in in the background even while you are not testing, so a broken
  script can lock an account. Get **Test authentication now** passing first.
- **Invalid-session pattern:** find out what a dead session looks like. Take a
  request from Proxy history into Repeater, swap in an expired or logged-out token,
  and send it. Pick something that only that response contains, such as
  `WWW-Authenticate: Bearer error="invalid_token"` or `(?i)your session has
  expired`. The status line and headers are matched ignoring case, so header
  patterns also match the lower-case names HTTP/2 uses. The body is matched
  exactly as written unless you add `(?i)`. The pattern is matched against the
  status line, headers and body of every replay, so a pattern that also matches
  healthy pages causes a login and a second replay for every request.
- **Session-check URL:** a cheap `GET` that any logged-in user can read, such as
  `/api/me` or the profile page. A recorder import fills it in when the proof
  request was a `GET`. **Healthy-session pattern:** with it empty, the check does
  not follow redirects and counts only a 2xx as alive, so a dead session that gets
  a `401`/`403`, another 4xx/5xx, or a redirect to the login page is caught. Set it
  if a dead session gets a `200` login page there, to something only a live session
  returns, for example `"email"\s*:`. Set it too if the URL redirects even when
  logged in (or point the check at the redirect's target): otherwise every probe
  reads as dead and each denial costs a re-auth.
- **Without a session-check URL, re-authenticate speculatively when a replay is
  denied** is on by default. It only matters when no session-check URL is set:
  a configured check URL is always probed on a denial, whatever this setting says.
  Leave it on unless logins are expensive or rate-limited. When it is off and there
  is no check URL, only the invalid-session pattern and the session lifetime timer
  detect expiry.

### 7. Capture the baseline

The baseline is the request and response exactly as Burp saw them, carrying
whatever credentials your browser sent. Every identity's replay is compared against
it. So browse through Burp (Burp's browser or a proxied one) **as the user who owns
the data**, and the baseline user does not have to be a configured identity.

If the baseline user is also an enabled identity, that column is compared against
its own traffic and reads **Bypassed!** on nearly every row. That is a useful
positive control while you tune settings, as it proves the comparison works. But it
fills **Findings only** with rows that are not findings, so untick **Include this
identity in tests** for it before the real run.

Plan one browsing pass per question you want answered:

- **Vertical (privilege escalation):** browse as the administrator, through every
  admin function, with the lower-privilege users as identities. A low-privilege
  identity that reads **Bypassed!** reached an admin function.
- **Horizontal (other users' data):** browse as user A, opening A's own records
  (orders, documents, profile, invoices), with user B (same role) as an identity.
  B reading **Bypassed!** on A's record is a finding. Then swap: browse as B, with A
  as the identity.
- **Cross-tenant:** the same as horizontal, with the other tenant's users as
  identities.

Use **Clear** on the Results tab between passes if you want each pass on its own.
It has no confirmation, it also deletes the results stored in the project, and it
resets **Test each endpoint only once**, so the next pass tests everything again.
Export first (step 9) if you need the earlier rows.

### 8. Run the tests

Two ways in, which you can mix:

- **Auto-test:** tick **Auto-test in-scope traffic** on the Results tab and
  browse. Each response that passes the filters is replayed in the background. The
  status line shows how many were tested, queued, skipped by filters and dropped.
- **On demand:** right-click any request anywhere in Burp (Proxy history, site map,
  Logger, Repeater) → **Send to Auth Check**, for one or several requests. This
  ignores every filter, the dedupe and Burp's target scope. Only each identity's
  **Only URLs matching:** still applies. The rows show source **Manual**. The
  extension switches its own view to **Results**, but Burp stays on the tab you were
  in.

Read step 1 again before you browse anything that changes state with auto-test on:
each such request is sent `1 + N` times, and the filters in step 4 are the only
safeguard. On a production system, the safest routine is auto-test with
state-changing methods in **Skip these HTTP methods:**, then **Send to Auth Check**
for the individual write requests you have agreed to test.

### 9. Triage the results

Each row is one captured request. **Status** and **Length** are the baseline's;
then there is a verdict column for **Unauthenticated** and for each enabled
identity. Hover a verdict cell for the explanation, and click a column header twice
to sort the worst first. [Reading the verdicts](#reading-the-verdicts) has the full
table.

| Verdict | What to do |
|---|---|
| **Bypassed!** | Confirm it (below). Check the row's **Notes** first: *endpoint appears public* means the unauthenticated replay also succeeded, so the identity results prove nothing. The identity cells still read **Bypassed!** and still count as findings, so you have to discount them yourself |
| **Review** | Read the response. Usually it is the identity's own data, which is correct behaviour. It is a finding if it contains anything of the baseline user's: names, ids, amounts. Also look here for a non-2xx baseline, which can never produce **Bypassed!** |
| **Enforced** | Nothing to do, unless you suspect the denied body pattern is matching a normal page. Spot-check a few |
| **Auth failed** | Nothing was tested. Fix the identity (**Test authentication now**, **Login traffic**), then select the rows and **Retest selected** |
| **Error** | The replay failed or got no response. Check the target is up and **Response timeout (ms):** is long enough, then retest |
| **-** | Not replayed: the URL is outside that identity's **Only URLs matching:** |

**Confirming a bypass.** Select the row. The **Variants** list on the left
auto-selects the worst variant, and **Request**/**Response** show that replay
exactly as sent. Compare it with **Baseline (as captured)**:

1. Check the replayed request carries the identity's credentials and none of the
   baseline user's (**Auth applied to this replay** in the **Verdict** box lists
   what was applied; the line is missing when the replay re-authenticated, so
   check the **Request** pane directly then).
2. Check the response contains the baseline user's data, not a generic page that
   happens to match.
3. With the identity selected in **Variants**, press **Send to Repeater**.
   Double-clicking the row sends the worst variant, not the one you picked. The
   Repeater tab is named `AuthChk <identity>`. Send it
   again by hand, and if the session has since expired, run **Test authentication
   now** and paste the fresh token in. A response that still returns the other
   user's data is your evidence. Select **Baseline (as captured)** first to send the
   original instead.

**Retest selected** sends the selected rows again as new **Manual** rows, compared
against the original baseline response. If the data has changed since you captured
it, expect **Review** rather than **Bypassed!**.

**Findings only** shows only rows with at least one **Bypassed!**. It hides
**Review** rows, so do not rely on it alone.

**Export CSV...** writes every row currently in the Results table with each
variant's verdict and explanation, for the report. It ignores **Findings only** and
the sort. The table holds at most **Keep at most N results** rows (oldest dropped
first), and the CSV has a column only for each identity currently enabled, so on a
long test raise the cap or export after each pass.

### 10. Scanner and Intruder

Auth Check publishes every identity as a Burp session-handling action named
**Auth Check: authenticate as &lt;identity&gt;**. A session-handling rule that
invokes it rewrites each matching request with that identity's credentials before
it goes out, in the same way as a replay: the **Strip these headers first:**
headers come off, then the script's headers, cookies and params and the static
headers go on. That is how you run an active scan or an Intruder attack as one of
your test users, without pasting a token that dies halfway through.

**Set up a rule for the identity you want to scan as.** Other identities stay
idle: an action does nothing until a rule invokes it.

1. Get **Test authentication now** passing for the identity first. A failed login
   is not reported to the scan (see below).
2. Burp → **Settings** → **Sessions** → **Session handling rules** → **Add**. Give
   the rule a description that names the identity, such as "Scan as User A".
3. **Rule actions** → **Add** → **Invoke a Burp extension** → pick **Auth Check:
   authenticate as User A**. Add only that one action.
4. **Scope** tab → **Tools scope**: tick **Scanner** (and **Intruder** if you
   fuzz as this user too). Leave **Proxy** out, or your baseline browsing is
   rewritten as the identity. Leave **Extensions** out, or every Auth Check replay
   is rewritten as well, and every identity's column reads as this one.
5. **URL scope**: **Use suite scope**, or a custom scope covering only the target.
6. Look at the other rules in the list. Burp runs every enabled rule whose scope
   matches, top to bottom, so:
   - Two rules invoking different Auth Check actions for the same tool and URL
     means the last one wins. Keep exactly one enabled per tool.
   - Burp's default **Use cookies from Burp's cookie jar** rule covers Scanner.
     The cookie jar holds the cookies from your own browsing, so it can put the
     baseline user's session cookie back on top of the identity's. Untick
     **Scanner** in that rule's tool scope, or move the Auth Check rule below it.
7. Start the scan. Burp has no per-scan session setting: the rules apply to every
   scan in the project while they are enabled.

**Check it before a long scan.** Run a short scan or a single Intruder request,
then look at the requests in **Logger**. They should carry the identity's
credentials and nothing of the baseline user's. A session cookie under a
different name, or an `Authorization`, `Api-Key` or similar header, survives
unless it is in the identity's **Strip these headers first:** list (step 5). If
it survives, the server sees two users at once, and the scan results are for
whichever one it prefers.

**Switching to another identity.** Edit the rule's action and pick the other
identity, or keep one rule per identity and enable only the one you are
scanning as. Renaming an identity changes its action name, so check the rule
still points at it after a rename.

**Keep the session alive for the length of the scan.** The action only sees the
outgoing request, never the response. That means the invalid-session pattern and
the session-check URL (step 6) never fire for scanner or Intruder traffic.
Scanner requests trigger a login in two cases only: when there are no
credentials yet, or when the credentials are older than the identity's **Session
lifetime (seconds, 0 = no timer):**. So:

- Set the session lifetime for any identity you scan as. With it at 0 and a
  session that expires, the rest of the scan goes out with dead credentials, and
  every check after that point is run unauthenticated without any warning.
- A scan can still kill the session early, for example when a payload reaches a
  logout, password-change or account-lock endpoint. Exclude those from the scan
  (Burp's scan configuration, or the URL scope of the rule), and watch for a wall
  of `401`/`302` responses in Logger. **Test authentication now** forces a fresh
  login, and the scan picks the new credentials up on its next request.
- Auto-testing in the same project shares the session: when a replay
  re-authenticates the identity, the scan uses the new session too.

**What happens when a request cannot be authenticated.**

- If the script fails, the request goes out **unchanged** and the error is
  written to Burp → **Extensions** → **Installed** → Auth Check → **Errors**.
  Further attempts wait 3 seconds after a failure, so a broken script cannot
  hammer the login endpoint, but scan requests sent during that wait are not
  authenticated either. If a scan's issues look like an anonymous user's, look
  there first.
- A request outside the identity's **Only URLs matching:** also goes out
  unchanged, with nothing logged. That stops the identity's credentials leaking
  to another application, but means the request keeps whatever credentials it
  already had.
- Disabled identities still have actions registered. Unticking **Include this
  identity in tests** does not stop a rule that uses it. Disable the rule
  instead.

**Leave Scanner and Intruder unticked under Test traffic from:** (step 4). With
them ticked, every scan request is also replayed as every other identity and
once with no credentials, which multiplies the scan by `N + 1` and fills the
Results table with scanner payloads.

### 11. Wrapping up

1. Export the results with **Export CSV...** and save the Burp project.
2. **Identities → Export all...** for a backup of the identities, credentials and
   scripts that does not depend on the project file. It does not include login
   traffic.
3. In Chrome, open **Saved recordings** from the recorder popup, pick each
   recording from the dropdown and press **Delete recording**. Remove the recorder
   if the profile is shared.
4. Treat the project file, the identities export, the CSV and any recorder
   download as sensitive. All of them hold credentials or application data in
   clear text. Archive or destroy them according to the engagement's data-handling
   terms, and ask the client to disable the test accounts.

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

## Recording a login in Chrome

Writing the script by hand is the slow part when the login is a multi-hop redirect
dance. [`chrome-extension/`](chrome-extension/) is a companion recorder that writes
it for you: log in once in a Chrome tab, and it produces the script plus an
identities file for **Identities → Import...**.

It works out which requests the session depends on and drops the rest. Every value
the server issued along the way (CSRF tokens, form actions, redirect `Location`s,
authorization codes, cookies, bearer tokens) is pulled from the response that issued
it, so each run gets fresh ones. What you typed becomes a `params` declaration, so
one script serves every identity. A TOTP code becomes a `totpSecret` param and is
generated on each run. Each step checks its status against the recording and fails
at the step that changed.

The generated scripts use the same `http` helper as the templates and are meant to
be read and edited. The recorder's golden outputs are compiled and run by
`RecordedScriptsTest` against a server that issues different values on every run,
so the generator and the engine are tested together.
[`chrome-extension/README.md`](chrome-extension/README.md) covers installing,
recording and its limits.

---

## Keeping short-lived sessions alive

Per identity, on the **Session lifetime** tab:

- **Session lifetime (seconds, 0 = no timer)** — if the app expires sessions on a timer, state it.
  Background re-auth happens at 80% of that age. `0` disables the timer.
- **Invalid-session pattern** — a regex matched against the replayed response's
  status line, headers and body. This is the reliable signal; on a match the session
  is rebuilt and the request replayed once. Good values:
  `(?i)"error"\s*:\s*"(invalid_token|token_expired)"`, `(?i)please log in again`.
- **Session-check URL** + **Healthy-session pattern** — a cheap authenticated
  endpoint used to settle whether a `401`/`403` meant "expired" or "not allowed".
  Leave the pattern empty to accept only a 2xx; a redirect (such as one to the
  login page) counts as a dead session.
- **Without a session-check URL, re-authenticate speculatively when a replay is
  denied** — on by default. With no session-check URL, a denied replay then
  triggers one speculative re-auth per identity per 10s. Untick it to treat those
  denials as enforcement. It has no effect while a session-check URL is set: the
  check URL is probed on every denial (cached for 5s) and decides.

Configuring the invalid-session pattern is the single highest-value thing you can do
for a fast-expiring target. Without it the extension falls back to rate-limited
guessing, which is safe but slower to react.

---

## Reading the verdicts

| Verdict | Meaning |
|---|---|
| **Bypassed!** | Same status and near-identical body as the baseline: this identity reached the resource. Your finding. |
| **Enforced** | The server refused — denied status code, denial pattern in the body, or a redirect to login. |
| **Review** | Different from the baseline but not a recognisable denial. Usually the identity's own data; sometimes a partial leak. Read it. |
| **Auth failed** | No session could be established, so nothing was proven. Fix the script first. |
| **Error** | The replay itself failed — connection refused, timeout. |
| **-** | Not replayed: the URL is outside this identity's **Only URLs matching** scope. |

Select a row, then pick a variant from the **Variants** list to see its full request
and response side by side, plus the reasoning behind the verdict; the worst variant is
selected for you. Verdict columns sort by severity, least severe first, so click the
header again to put the worst first. The
sort you choose is remembered in the project — it is stored against the column's
identity rather than its position, so adding or removing an identity does not leave
you sorted by the wrong column. Hovering
a verdict cell shows the explanation, and hovering a URL shows it in full. **Findings
only** hides everything but rows with a **Bypassed!**. **Export CSV...** writes every
row with each verdict and its explanation, whatever the filter.

---

## Avoiding false positives

Two situations make a naive tool cry wolf, and both are handled explicitly:

**A public endpoint.** If the unauthenticated replay also succeeds, then every
identity "bypassing" it is expected. Those rows are annotated *endpoint appears
public*, and the Unauthenticated column makes it obvious at a glance — which is the
main reason to leave that replay switched on. The identity cells still read
**Bypassed!** and still count under **Findings only**, so discount them yourself.

**A baseline that was not a success.** Comparing against a `404` or a `500` proves
nothing. Rather than claim a bypass because two `404`s match, those rows degrade to
**Review** and say why. A replay that is a recognised denial still reads
**Enforced**, because denial is checked first.

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

The action honours the identity's scope (below): a request outside it passes through
unchanged, so a rule scoped wider than the identity cannot leak its credentials.

The action only sees the request, so for scanner and Intruder traffic a new login
happens only on the identity's session-lifetime timer, never because a response
showed the session had died. [Step 10 of the user guide](#10-scanner-and-intruder)
covers scanning as one identity, the cookie-jar rule, and what a failed login
does to a scan.

---

## Several apps in one project

When one engagement covers several applications, each with its own users, scope each
identity to its app: **Identities → Credentials → Only URLs matching**. It is a regex
searched in the full URL, so `^https://app1\.example\.com/` fences an identity to
one host, and `^https://portal\.example\.com/billing/` to one app on a shared host.

A request outside an identity's scope is never replayed as that identity; its cell
shows `-` and the tooltip says why. When no identity's scope matches and the
unauthenticated variant is off, auto-test skips the request entirely. Leave the
field empty to use the identity everywhere, which is how every identity behaved
before. An invalid regex matches nothing, and the editor says so, rather than
falling open and replaying the identity everywhere.

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
> Use **Identities → Export all...** for a backup that does not depend on any of this.
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

- **Store tested requests and responses in the Burp project** — off writes nothing,
  neither results nor login traffic (default on).
- **Store only rows worth revisiting (bypassed, review, auth failed)** — keeps only
  rows where at least one identity's verdict is **Bypassed!**, **Review** or **Auth
  failed**. Enforced rows, which are usually the bulk, are discarded, and so are
  **Error** rows.
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

Nothing on the Settings tab takes effect until you press **Apply**. **Revert**
discards unapplied edits; **Restore defaults** resets every setting at once (after a
confirmation) and leaves identities alone. The Results tab's **Auto-test in-scope
traffic** checkbox is the same setting as **Automatically test traffic as it
arrives**, and applies immediately.

**What gets tested** — auto-test on/off; test unauthenticated; restrict to Burp
scope; which tools' traffic to watch (Proxy and Repeater by default); dedupe by
endpoint (method, host, port and path); whether a different set of parameter names,
cookie names included, makes a different endpoint (on); skip static resources (`css,
js, mjs, map, png, jpg, jpeg, gif, svg, ico, webp, avif, woff, woff2, ttf, eot, mp4,
mp3, pdf`); skip baseline status codes (`301, 302, 304, 404`); **skip HTTP methods**;
URL include/exclude regexes.

Filtered methods never reach the results at all. `OPTIONS` is skipped by default: a
CORS preflight carries no authorisation decision, and testing one per request would
triple the traffic for nothing. Clear the list to test every method.

Requests sent by extensions are **never** auto-tested, regardless of settings —
otherwise the extension would test its own replays forever. "Send to Auth Check"
ignores every filter, including dedupe and Burp's target scope; only each identity's
own URL scope still applies.

**Judging the responses** — same-response threshold (default 95%); comparison byte cap
(262144);
Burp variations analyser instead of similarity; follow redirects on replay (off by
default, so a 302 to `/login` reads as enforcement).

**What counts as "access denied"** — status codes (401, 403); a body regex, checked
at any status; whether a redirect to a login URL counts, and the login URL pattern.
The defaults are on the Settings tab, and [step 4 of the user
guide](#4-configure-settings-for-the-engagement) covers tuning them.

**Unauthenticated replay** — which headers to strip (`Authorization,
Proxy-Authorization, Cookie, X-Api-Key, Api-Key, X-Auth-Token, X-Access-Token,
X-Session-Token, X-CSRF-Token, X-XSRF-Token`).

**Storing results in the project** — whether to store tested requests and responses,
whether to limit that to rows worth revisiting, and the storage cap.

**Performance** — worker threads; queue capacity (takes effect only after the
extension is reloaded); response timeout; script timeout; result cap. When the queue is full, work is shed and the count is shown in the status
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
chrome-extension/                Companion recorder: a recorded login -> script + identities
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

152 JUnit tests cover the parts that decide whether you have a finding, and the parts
that decide whether you still have it tomorrow:

- **Verdicts** — bypass/enforced/review rules, denial detection, unsuccessful baselines.
- **Similarity** — the Dice metric and its token masking, in both directions: session
  noise must not hide a bypass, and one user's data must not masquerade as another's.
- **Request rewriting** — strip order, cookie merging, static-header precedence.
- **The Groovy engine**, end to end — credentials, `vars` persistence, JSON parsing,
  failure reporting, timeouts.
- **Recorded scripts** — the Chrome recorder's generated scripts compile, declare
  what they read, and log in against a fake server issuing fresh tokens, cookies,
  form actions, redirects and TOTP codes.
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
