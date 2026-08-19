package com.omnicybersecurity.authcheck.integration;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import com.omnicybersecurity.authcheck.auth.SessionManager;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.engine.RequestMutator;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.Identity;

import java.util.ArrayList;
import java.util.List;

/**
 * Publishes one Burp session-handling action per identity.
 *
 * <p>This is what makes the auth scripts useful beyond this extension's own
 * tables: add a session-handling rule in Burp's project options that invokes
 * "Auth Check: &lt;identity&gt;", and Scanner, Intruder and Repeater traffic all
 * get that identity's live credentials, re-authenticating whenever the session
 * dies. Exactly the problem short-lived sessions cause during a scan.
 *
 * <p>Registrations are rebuilt whenever the identity roster changes, since Burp
 * takes the action's name at registration time.
 */
public final class SessionActionRegistrar {

    private final MontoyaApi api;
    private final Configuration configuration;
    private final SessionManager sessionManager;
    private final RequestMutator mutator;
    private final List<Registration> registrations = new ArrayList<>();

    public SessionActionRegistrar(MontoyaApi api, Configuration configuration, SessionManager sessionManager) {
        this.api = api;
        this.configuration = configuration;
        this.sessionManager = sessionManager;
        this.mutator = new RequestMutator(configuration);
    }

    /** Drops the current actions and registers one per identity. */
    public synchronized void refresh() {
        for (Registration registration : registrations) {
            if (registration.isRegistered()) {
                registration.deregister();
            }
        }
        registrations.clear();

        for (Identity identity : configuration.identities()) {
            String identityId = identity.id();
            registrations.add(api.http().registerSessionHandlingAction(new SessionHandlingAction() {
                @Override
                public String name() {
                    return "Auth Check: authenticate as " + identity.name();
                }

                @Override
                public ActionResult performAction(SessionHandlingActionData data) {
                    return applyIdentity(identityId, data.request());
                }
            }));
        }
    }

    private ActionResult applyIdentity(String identityId, HttpRequest request) {
        Identity identity = configuration.identityById(identityId);
        if (identity == null) {
            return ActionResult.actionResult(request);
        }
        try {
            AuthMaterial material = sessionManager.materialFor(identity);
            if (material == null) {
                api.logging().logToError("[auth-check] Session handling action could not authenticate as '"
                        + identity.name() + "': " + sessionManager.statusFor(identity));
                return ActionResult.actionResult(request);
            }
            return ActionResult.actionResult(mutator.applyIdentity(request, identity, material));
        } catch (Exception e) {
            api.logging().logToError("[auth-check] Session handling action failed for '"
                    + identity.name() + "'", e);
            return ActionResult.actionResult(request);
        }
    }

    public synchronized void shutdown() {
        for (Registration registration : registrations) {
            if (registration.isRegistered()) {
                registration.deregister();
            }
        }
        registrations.clear();
    }
}
