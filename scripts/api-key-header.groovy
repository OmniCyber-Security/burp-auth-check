/*
 * Static API key or token in a header
 *
 * The simplest possible identity: no login flow, just a value you already have.
 * Use this when the application authenticates with a long-lived API key, or when
 * you have pasted a token grabbed by hand and only need it applied consistently.
 *
 * If the key never changes you do not need a script at all -- set the header
 * under Request rewriting -> "Always set these headers" instead. A script is
 * worth it when the value comes from a credential variable, so the identity can
 * be exported and shared without editing the header by hand.
 */

params {
    param 'token', type: SECRET, required: true, label: 'API key or token',
          help: 'Sent as "Authorization: Bearer <token>" on every replayed request'
}

log.info "Using a static token for ${identity}"

return [headers: ['Authorization': "Bearer ${creds.token}"]]
