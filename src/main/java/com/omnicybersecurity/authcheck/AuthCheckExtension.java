package com.omnicybersecurity.authcheck;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.omnicybersecurity.authcheck.auth.AuthScriptEngine;
import com.omnicybersecurity.authcheck.auth.SessionManager;
import com.omnicybersecurity.authcheck.config.ConfigStore;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.ResultsRepository;
import com.omnicybersecurity.authcheck.engine.AuthCheckEngine;
import com.omnicybersecurity.authcheck.engine.RecordStore;
import com.omnicybersecurity.authcheck.integration.AuthCheckContextMenu;
import com.omnicybersecurity.authcheck.integration.SessionActionRegistrar;
import com.omnicybersecurity.authcheck.integration.TrafficHandler;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.ui.AuthCheckTab;
import com.omnicybersecurity.authcheck.util.BuildInfo;

import javax.swing.SwingUtilities;
import java.util.List;

/**
 * Entry point. Wires the configuration, session manager, engine and UI together
 * and registers the extension's hooks with Burp.
 */
public final class AuthCheckExtension implements BurpExtension {

    private static final String NAME = "Auth Check - authorisation testing";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME + " " + BuildInfo.describe());
        api.logging().logToOutput("Auth Check build " + BuildInfo.describe());

        Configuration configuration = new Configuration(new ConfigStore(api));
        configuration.load();

        ResultsRepository repository = new ResultsRepository(api, configuration.settings());

        AuthScriptEngine scriptEngine = new AuthScriptEngine(api, configuration.settings());
        SessionManager sessionManager = new SessionManager(api, configuration, scriptEngine);
        RecordStore records = new RecordStore(configuration.settings(), repository);
        AuthCheckEngine engine = new AuthCheckEngine(api, configuration, sessionManager, records);

        // Login traffic is stored beside the script that produced it, so a finding
        // can be reproduced from the project alone.
        sessionManager.onAuthTranscript(repository::storeAuthTranscript);

        restoreFromProject(api, configuration, repository, records, engine, sessionManager);

        SessionActionRegistrar sessionActions = new SessionActionRegistrar(api, configuration, sessionManager);
        sessionActions.refresh();
        configuration.onIdentitiesChanged(sessionActions::refresh);

        api.http().registerHttpHandler(new TrafficHandler(engine, api.logging()));

        // The UI must be built on the event thread, and the context menu needs a
        // reference to it, so registration happens once the tab exists.
        SwingUtilities.invokeLater(() -> {
            AuthCheckTab tab = new AuthCheckTab(api, configuration, records, engine, sessionManager,
                    scriptEngine, repository);
            api.userInterface().registerSuiteTab("Auth Check", tab);
            api.userInterface().registerContextMenuItemsProvider(
                    new AuthCheckContextMenu(engine, ignored -> tab.focusResults()));
            api.logging().logToOutput("Auto-testing is "
                    + (configuration.settings().autoTestEnabled() ? "ON" : "OFF")
                    + ". See the Help tab for the auth script reference.");
        });

        api.extension().registerUnloadingHandler(() -> {
            configuration.save();
            engine.shutdown();
            sessionManager.shutdown();
            sessionActions.shutdown();
            scriptEngine.shutdown();
            // Last, so anything still queued reaches the project before we go.
            repository.shutdown();
            api.logging().logToOutput("Auth Check unloaded.");
        });
    }

    /** Brings back the previous session's identities, results and login traffic. */
    private void restoreFromProject(MontoyaApi api, Configuration configuration, ResultsRepository repository,
            RecordStore records, AuthCheckEngine engine, SessionManager sessionManager) {
        int identityCount = configuration.identities().size();
        api.logging().logToOutput("Auth Check loaded. " + identityCount + " identit"
                + (identityCount == 1 ? "y" : "ies") + " restored from this project.");

        try {
            List<AuthTestRecord> stored = repository.load();
            if (!stored.isEmpty()) {
                // Continue numbering where the last session stopped, so record
                // numbers stay unique across restarts.
                engine.resumeIndexingAfter(records.restore(stored));
                api.logging().logToOutput("Restored " + stored.size()
                        + " stored result(s) from this project.");
            }
        } catch (Exception e) {
            api.logging().logToError("[auth-check] Could not restore stored results", e);
        }

        for (Identity identity : configuration.identities()) {
            try {
                sessionManager.restoreTranscript(identity.id(), repository.loadAuthTranscript(identity.id()));
            } catch (Exception e) {
                api.logging().logToError("[auth-check] Could not restore login traffic for "
                        + identity.name(), e);
            }
        }
    }
}
