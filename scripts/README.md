# Auth scripts

Working examples, and the reference for writing your own.

These files are the **single source** for the templates offered in the extension's
**Identities → Auth script → Insert template** menu. The build copies them into the
jar; they are not duplicated anywhere in the Java.

## The files

| File | Pattern |
|---|---|
| [`api-key-header.groovy`](api-key-header.groovy) | Static API key or token — no login flow |
| [`json-login-bearer.groovy`](json-login-bearer.groovy) | JSON login → bearer token |
| [`form-login-session-cookie.groovy`](form-login-session-cookie.groovy) | HTML form login with CSRF → session cookie |
| [`oauth2-refresh-token.groovy`](oauth2-refresh-token.groovy) | Password grant, reusing the refresh token via `vars` |
| [`csrf-token-per-request.groovy`](csrf-token-per-request.groovy) | Session cookie plus a CSRF token in the body |
| [`login-then-assume-role.groovy`](login-then-assume-role.groovy) | Two-step: log in, then elevate to a role |
| [`totp-mfa-login.groovy`](totp-mfa-login.groovy) | Login behind a TOTP second factor, code generated |
| [`entra-id-oidc-totp.groovy`](entra-id-oidc-totp.groovy) | Entra ID authorization-code sign-in, TOTP second factor |
| [`_api-reference.groovy`](_api-reference.groovy) | Every binding and helper, with types. Not a template |

## Declaring credentials

Every example starts with a `params` block naming the credential variables it reads.
That block is what the extension's **Credentials** tab renders as a form, so a tester
gets labelled fields, masked secrets, defaults and a required-field check instead of
a comment to guess from:

```groovy
params {
    param 'base',       type: URL,    required: true, label: 'Base URL'
    param 'username',   type: STRING, required: true
    param 'password',   type: SECRET, required: true
    param 'totpSecret', type: SECRET, help: 'Base32 secret from the enrolment QR code'
    param 'scope',      type: STRING, default: 'openid profile offline_access'
}
```

Types are `STRING`, `SECRET`, `INT`, `BOOL`, `URL`, `CHOICE` (with `choices: [...]`)
and `TEXT`. A param is optional unless it says `required: true`; a `default:` is
filled in when the field is left empty, so the script can read `creds.scope` without
a `?:` fallback, and cannot be combined with `required: true`.

The block is parsed out of the source without running the script, so everything in it
must be a literal. Help text longer than a line joins with a **trailing** `+` — a
leading `+` on the next line starts a new statement in Groovy, and is reported rather
than silently keeping half the sentence.

A test asserts that every example here declares its params, that every declared param
is actually read, and that anything secret-looking is typed `SECRET`. Guarding a
missing credential by hand is no longer needed — `required: true` refuses the run
before the first request, and names the field.

## Adding one

Drop a `.groovy` file in this directory and rebuild. The build indexes it and it
appears in the template menu — there is no list to update.

**The first line of prose in the opening comment becomes the menu entry**, so keep it
short and descriptive:

```groovy
/*
 * HTML form login -> session cookie
 *
 * Longer explanation, credential variables expected, suggested settings...
 */
```

A file whose name starts with `_` is treated as reference material and is not
bundled as a template.

A test compiles every bundled script on each build, so a broken example fails CI
rather than turning up in someone's template menu.

## Editor support

Scripts are compiled against
[`AuthScriptBase`](../src/main/java/com/omnicybersecurity/authcheck/auth/AuthScriptBase.java),
which declares `creds`, `http`, `vars`, `log`, `api` and `identity` with real types,
plus `params` and the type constants used inside it.
That means an editor can complete and type-check them:

1. Open this repository, or any project, in an IDE with Groovy support.
2. Put `burp-auth-check-<version>.jar` on the project classpath — from
   [Releases](https://github.com/OmniCyber-Security/burp-auth-check/releases) or
   `build/libs/` after `./gradlew shadowJar`.
3. Write scripts in this directory. `http.` now lists every helper with its
   signature; `creds.` and `vars.` resolve as maps.

To make the typing explicit in a file you are editing outside this directory, name
the base class at the top:

```groovy
@groovy.transform.BaseScript com.omnicybersecurity.authcheck.auth.AuthScriptBase base
```

That line is optional — the engine applies the base class regardless — but it tells
the IDE what to resolve.

[`_api-reference.groovy`](_api-reference.groovy) is a runnable-looking summary of the
whole surface: every helper call, every return shape, and the two ways the engine
decides a script has failed. Read that first.

## The one that catches people

Cookies must be wrapped:

```groovy
return [cookies: http.cookies(resp)]   // correct
return http.cookies(resp)              // sets HEADERS named after your cookies
```

A bare map is the shorthand for headers, and `http.cookies(resp)` returns exactly
that shape. The script log warns when it happens, but it is worth knowing up front.
