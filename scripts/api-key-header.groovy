/*
 * Static API key or token in a header
 *
 * The simplest possible identity: no login flow, just a value you already have.
 * Use this when the application authenticates with a long-lived API key, or when
 * you have pasted a token grabbed by hand and only need it applied consistently.
 *
 * Credential variables expected on the identity:
 *   token - the key or token value
 *
 * If the key never changes you do not need a script at all -- set the header
 * under Request rewriting -> "Always set these headers" instead. A script is
 * worth it when the value comes from a credential variable, so the identity can
 * be exported and shared without editing the header by hand.
 */

if (!creds.token) {
    throw new IllegalStateException("No 'token' credential set on this identity")
}

log.info "Using a static token for ${identity}"

return [headers: ['Authorization': "Bearer ${creds.token}"]]
