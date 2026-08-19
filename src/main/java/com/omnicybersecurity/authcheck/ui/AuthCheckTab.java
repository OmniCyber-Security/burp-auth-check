package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.MontoyaApi;
import com.omnicybersecurity.authcheck.auth.AuthScriptEngine;
import com.omnicybersecurity.authcheck.auth.SessionManager;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.ResultsRepository;
import com.omnicybersecurity.authcheck.engine.AuthCheckEngine;
import com.omnicybersecurity.authcheck.engine.RecordStore;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;

/** The extension's suite tab. */
public final class AuthCheckTab extends JPanel {

    private final JTabbedPane tabs = new JTabbedPane();
    private final ResultsPanel resultsPanel;
    private final IdentitiesPanel identitiesPanel;

    public AuthCheckTab(MontoyaApi api, Configuration configuration, RecordStore records,
            AuthCheckEngine engine, SessionManager sessionManager, AuthScriptEngine scriptEngine,
            ResultsRepository repository) {
        super(new BorderLayout());

        this.resultsPanel = new ResultsPanel(api, configuration, records, engine, repository);
        this.identitiesPanel = new IdentitiesPanel(api, configuration, sessionManager, scriptEngine, repository);

        tabs.addTab("Results", resultsPanel);
        tabs.addTab("Identities", identitiesPanel);
        tabs.addTab("Settings", new SettingsPanel(configuration));
        tabs.addTab("Help", new HelpPanel(UiUtils.isDark(api)));

        tabs.addChangeListener(event -> {
            if (tabs.getSelectedComponent() == identitiesPanel) {
                identitiesPanel.refreshStatus();
            }
        });

        add(tabs, BorderLayout.CENTER);
    }

    /** Brings the Results tab forward, used after "Send to Auth Check". */
    public void focusResults() {
        SwingUtilities.invokeLater(() -> tabs.setSelectedComponent(resultsPanel));
    }
}
