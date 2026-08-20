package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.omnicybersecurity.authcheck.auth.AuthOutcome;
import com.omnicybersecurity.authcheck.auth.AuthScriptEngine;
import com.omnicybersecurity.authcheck.auth.ScriptParamExtractor;
import com.omnicybersecurity.authcheck.auth.SessionManager;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.IdentityTransfer;
import com.omnicybersecurity.authcheck.config.ResultsRepository;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Text;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * The Identities tab: define each user, their credentials, the script that keeps
 * them logged in, and how to tell when their session has died.
 */
public final class IdentitiesPanel extends JPanel {

    private final MontoyaApi api;
    private final Configuration configuration;
    private final SessionManager sessionManager;
    private final AuthScriptEngine scriptEngine;
    private final ResultsRepository repository;

    private final DefaultListModel<Identity> listModel = new DefaultListModel<>();
    private final JList<Identity> identityList = new JList<>(listModel);

    private final JTextField nameField = new JTextField(24);
    private final JCheckBox enabledBox = new JCheckBox("Include this identity in tests");
    private final JTextField notesField = new JTextField(24);

    private final CredentialsForm credentialsForm;

    private final JTextField stripHeadersField = new JTextField(40);
    private final JTextArea staticHeadersArea;
    private final JTextField tokenHeaderField = new JTextField(20);

    private final JTextField refreshIntervalField = new JTextField(8);
    private final JTextField sessionInvalidRegexField = new JTextField(40);
    private final JCheckBox reauthOnDeniedBox = new JCheckBox(
            "Re-authenticate when a replay is denied and the session cannot be proven alive");
    private final JTextField sessionCheckUrlField = new JTextField(40);
    private final JTextField sessionValidRegexField = new JTextField(40);

    private final JTextArea scriptArea;
    private final JTextArea authLogArea;
    private final JLabel sessionStatusLabel = new JLabel(" ");

    /** The login exchanges this identity's script performed, kept in the project. */
    private final DefaultListModel<TranscriptEntry> transcriptModel = new DefaultListModel<>();
    private final JList<TranscriptEntry> transcriptList = new JList<>(transcriptModel);
    private final HttpRequestEditor authRequestEditor;
    private final HttpResponseEditor authResponseEditor;
    private final JLabel transcriptSummary = new JLabel(" ");

    /** One request/response the auth script sent while logging in. */
    private record TranscriptEntry(String label, HttpRequestResponse exchange) {
        @Override
        public String toString() {
            return label;
        }
    }

    /** Guards the field-to-model bindings while an identity is being loaded. */
    private boolean loading;
    private final Timer saveTimer;
    /** Coalesces identity-roster changes (renames) that trigger re-registration. */
    private final Timer structureTimer;
    /** Waits for the tester to stop typing before re-reading the params block. */
    private final Timer paramsTimer;

    public IdentitiesPanel(MontoyaApi api, Configuration configuration, SessionManager sessionManager,
            AuthScriptEngine scriptEngine, ResultsRepository repository) {
        super(new BorderLayout());
        this.api = api;
        this.configuration = configuration;
        this.sessionManager = sessionManager;
        this.scriptEngine = scriptEngine;
        this.repository = repository;
        this.authRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.authResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        this.scriptArea = UiUtils.codeArea(api, 18, 80);
        this.staticHeadersArea = UiUtils.codeArea(api, 3, 40);
        this.authLogArea = UiUtils.codeArea(api, 8, 80);
        this.authLogArea.setEditable(false);

        this.credentialsForm = new CredentialsForm(api, this::onFieldEdited);

        // Persisting on every keystroke would rewrite the project constantly.
        this.saveTimer = new Timer(1_200, e -> configuration.save());
        this.saveTimer.setRepeats(false);
        this.structureTimer = new Timer(1_200, e -> configuration.identitiesChanged());
        this.structureTimer.setRepeats(false);
        // Re-deriving the credentials form means parsing the script, so it waits
        // for a pause in typing rather than running on every keystroke.
        this.paramsTimer = new Timer(500, e -> refreshDeclaredParams());
        this.paramsTimer.setRepeats(false);

        buildUi();
        reloadList();
        bindFields();

        if (!listModel.isEmpty()) {
            identityList.setSelectedIndex(0);
        } else {
            setFieldsEnabled(false);
        }
    }

    // -- layout --------------------------------------------------------------

    private void buildUi() {
        identityList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        identityList.setCellRenderer(new IdentityRenderer());
        identityList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                loadSelected();
            }
        });

        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(BorderFactory.createTitledBorder("Identities"));
        left.add(UiUtils.scroll(identityList), BorderLayout.CENTER);
        left.add(buildListButtons(), BorderLayout.SOUTH);
        left.setPreferredSize(new Dimension(230, 400));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Credentials", buildCredentialsTab());
        tabs.addTab("Auth script", buildScriptTab());
        tabs.addTab("Login traffic", buildTranscriptTab());
        tabs.addTab("Session lifetime", buildSessionTab());
        tabs.addTab("Request rewriting", buildRewritingTab());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, tabs);
        split.setResizeWeight(0.0);
        split.setDividerLocation(240);
        add(split, BorderLayout.CENTER);
    }

    private JComponent buildListButtons() {
        JPanel buttons = new JPanel(new GridLayout(0, 1, 2, 2));

        JButton add = new JButton("Add");
        add.addActionListener(e -> {
            Identity identity = Identity.createNew("User " + (listModel.size() + 1));
            configuration.add(identity);
            reloadList();
            identityList.setSelectedValue(identity, true);
        });
        buttons.add(add);

        JButton duplicate = new JButton("Duplicate");
        duplicate.addActionListener(e -> {
            Identity current = identityList.getSelectedValue();
            if (current != null) {
                Identity copy = current.duplicate();
                configuration.add(copy);
                reloadList();
                identityList.setSelectedValue(copy, true);
            }
        });
        buttons.add(duplicate);

        JButton remove = new JButton("Remove");
        remove.addActionListener(e -> {
            Identity current = identityList.getSelectedValue();
            if (current == null) {
                return;
            }
            int choice = JOptionPane.showConfirmDialog(this,
                    "Remove '" + current.name() + "' and its stored credentials from this project?",
                    "Auth Check", JOptionPane.OK_CANCEL_OPTION);
            if (choice == JOptionPane.OK_OPTION) {
                sessionManager.forget(current.id());
                repository.forgetIdentity(current.id());
                configuration.remove(current);
                reloadList();
                if (!listModel.isEmpty()) {
                    identityList.setSelectedIndex(0);
                } else {
                    clearFields();
                    setFieldsEnabled(false);
                }
            }
        });
        buttons.add(remove);

        JButton export = new JButton("Export all...");
        export.setToolTipText("Save every identity, credential and script to a file");
        export.addActionListener(e -> exportIdentities());
        buttons.add(export);

        JButton importButton = new JButton("Import...");
        importButton.setToolTipText("Add identities from a previously exported file");
        importButton.addActionListener(e -> importIdentities());
        buttons.add(importButton);

        JPanel order = new JPanel(new GridLayout(1, 2, 2, 2));
        JButton up = new JButton("Up");
        up.addActionListener(e -> moveSelected(-1));
        order.add(up);
        JButton down = new JButton("Down");
        down.addActionListener(e -> moveSelected(1));
        order.add(down);
        buttons.add(order);

        return buttons;
    }

    private JComponent buildCredentialsTab() {
        UiUtils.Form form = new UiUtils.Form();
        form.add("Name:", nameField);
        form.addWide(enabledBox);
        form.add("Notes:", notesField);
        form.add("Credentials:", credentialsForm, true);
        form.addWide(UiUtils.hint(
                "A script that declares a params block gets a form with its own fields; one that does not gets "
                + "the name/value table. Either way the values are stored unencrypted in the Burp project file, "
                + "so treat the project as sensitive."));
        return form.panel();
    }

    private JComponent buildScriptTab() {
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));

        JComboBox<String> templates = new JComboBox<>();
        templates.addItem("Insert template...");
        ScriptTemplates.all().keySet().forEach(templates::addItem);
        templates.addActionListener(e -> {
            int index = templates.getSelectedIndex();
            if (index <= 0) {
                return;
            }
            String key = (String) templates.getSelectedItem();
            String body = ScriptTemplates.all().get(key);
            if (body != null && confirmOverwriteScript()) {
                scriptArea.setText(body);
                scriptArea.setCaretPosition(0);
            }
            templates.setSelectedIndex(0);
        });
        top.add(templates);

        JButton check = new JButton("Check syntax");
        check.addActionListener(e -> {
            String error = scriptEngine.validate(scriptArea.getText());
            if (error == null) {
                JOptionPane.showMessageDialog(this, "The script compiles.",
                        "Auth Check", JOptionPane.INFORMATION_MESSAGE);
            } else {
                showLongMessage("Script problem", error);
            }
        });
        top.add(check);

        JButton test = new JButton("Test authentication now");
        test.addActionListener(e -> testAuthentication());
        top.add(test);

        JButton load = new JButton("Load from file...");
        load.addActionListener(e -> loadScriptFromFile());
        top.add(load);

        JButton save = new JButton("Save to file...");
        save.addActionListener(e -> saveScriptToFile());
        top.add(save);

        JPanel scriptPanel = new JPanel(new BorderLayout());
        scriptPanel.setBorder(BorderFactory.createTitledBorder(
                "Groovy -- return e.g. [headers: ['Authorization': \"Bearer $token\"]]. See the Help tab."));
        scriptPanel.add(new JScrollPane(scriptArea), BorderLayout.CENTER);

        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Last authentication"));
        logPanel.add(new JScrollPane(authLogArea), BorderLayout.CENTER);
        logPanel.add(sessionStatusLabel, BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scriptPanel, logPanel);
        split.setResizeWeight(0.65);
        split.setDividerLocation(380);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(top, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JComponent buildTranscriptTab() {
        transcriptList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        transcriptList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                showSelectedExchange();
            }
        });

        JPanel left = new JPanel(new BorderLayout());
        left.setBorder(BorderFactory.createTitledBorder("Exchanges"));
        left.add(UiUtils.scroll(transcriptList), BorderLayout.CENTER);
        left.setPreferredSize(new Dimension(260, 300));

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                titled("Request", authRequestEditor.uiComponent()),
                titled("Response", authResponseEditor.uiComponent()));
        editors.setResizeWeight(0.5);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, editors);
        split.setResizeWeight(0.0);
        split.setDividerLocation(280);

        JPanel header = new JPanel(new BorderLayout());
        header.add(transcriptSummary, BorderLayout.NORTH);
        header.add(UiUtils.hint(
                "Exactly what this identity's script sent and received while logging in. Stored in the Burp "
                + "project alongside the script, so a finding can be reproduced from the project alone."),
                BorderLayout.SOUTH);
        header.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(header, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private static JComponent titled(String title, Component component) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(component, BorderLayout.CENTER);
        return panel;
    }

    private void loadTranscript(Identity identity) {
        transcriptModel.clear();
        authRequestEditor.setRequest(null);
        authResponseEditor.setResponse(null);
        if (identity == null) {
            transcriptSummary.setText(" ");
            return;
        }
        List<HttpRequestResponse> exchanges = sessionManager.lastTranscriptFor(identity);
        if (exchanges.isEmpty()) {
            transcriptSummary.setText("  No login traffic recorded yet -- press "
                    + "\"Test authentication now\" on the Auth script tab.");
            return;
        }
        int position = 1;
        for (HttpRequestResponse exchange : exchanges) {
            String label = position + ". " + exchange.request().method() + " "
                    + Text.abbreviate(exchange.request().path(), 44)
                    + (exchange.hasResponse() ? "  -> " + exchange.response().statusCode() : "  -> (no response)");
            transcriptModel.addElement(new TranscriptEntry(label, exchange));
            position++;
        }
        transcriptSummary.setText("  " + exchanges.size() + " exchange"
                + (exchanges.size() == 1 ? "" : "s") + " in the last login for " + identity.name());
        transcriptList.setSelectedIndex(0);
    }

    private void showSelectedExchange() {
        TranscriptEntry entry = transcriptList.getSelectedValue();
        if (entry == null || entry.exchange() == null) {
            authRequestEditor.setRequest(null);
            authResponseEditor.setResponse(null);
            return;
        }
        authRequestEditor.setRequest(entry.exchange().request());
        authResponseEditor.setResponse(entry.exchange().hasResponse() ? entry.exchange().response() : null);
    }

    private JComponent buildSessionTab() {
        UiUtils.Form form = new UiUtils.Form();
        form.addWide(UiUtils.title("Keeping short-lived sessions alive"));
        form.addWide(UiUtils.hint(
                "Set the lifetime if the app expires sessions on a timer. The extension re-runs the script at 80% "
                + "of that age, in the background, so replays never race the expiry."));
        form.add("Session lifetime (seconds, 0 = no timer):", refreshIntervalField);

        form.addWide(UiUtils.title("Noticing an expired session"));
        form.addWide(UiUtils.hint(
                "The invalid-session pattern is the reliable signal: if it matches a replayed response, the session "
                + "is rebuilt and the request replayed once. Regex, matched against status line, headers and body."));
        form.add("Invalid-session pattern:", sessionInvalidRegexField);

        form.addWide(UiUtils.hint(
                "A 401/403 is also the correct result of a passing authorisation check, so it is never treated as "
                + "expiry on its own. Give a session-check URL below and it is probed to settle the question; "
                + "without one, a speculative re-auth is allowed at most once every 10 seconds."));
        form.addWide(reauthOnDeniedBox);
        form.add("Session-check URL:", sessionCheckUrlField);
        form.add("Healthy-session pattern:", sessionValidRegexField);
        form.addWide(UiUtils.hint(
                "Leave the healthy-session pattern empty to accept any 2xx/3xx from the session-check URL."));
        form.addFiller();
        return UiUtils.scroll(form.panel());
    }

    private JComponent buildRewritingTab() {
        JPanel staticHeaders = new JPanel(new BorderLayout());
        staticHeaders.add(new JScrollPane(staticHeadersArea), BorderLayout.CENTER);
        staticHeaders.setPreferredSize(new Dimension(420, 90));

        UiUtils.Form form = new UiUtils.Form();
        form.addWide(UiUtils.hint(
                "How a captured request is turned into this identity's request: strip the original credentials, "
                + "apply the script's material, then force these static headers last."));
        form.add("Strip these headers first:", stripHeadersField);
        form.add("Always set these headers:", staticHeaders);
        form.addWide(UiUtils.hint("One per line, 'Name: value'. Applied after the script, so they always win."));
        form.add("Header for a bare token:", tokenHeaderField);
        form.addWide(UiUtils.hint(
                "Used when a script returns a plain string instead of a map."));
        form.addFiller();
        return UiUtils.scroll(form.panel());
    }

    // -- binding -------------------------------------------------------------

    private void bindFields() {
        bindText(nameField, this::currentIdentity, (identity, value) -> {
            identity.name(value);
            identityList.repaint();
            // Renaming re-registers every session-handling action and rebuilds the
            // results columns, so coalesce it instead of doing it per keystroke.
            structureTimer.restart();
        });
        bindText(notesField, this::currentIdentity, Identity::notes);
        bindText(stripHeadersField, this::currentIdentity, Identity::stripHeaders);
        bindText(tokenHeaderField, this::currentIdentity, Identity::tokenHeaderName);
        bindText(sessionInvalidRegexField, this::currentIdentity, Identity::sessionInvalidRegex);
        bindText(sessionCheckUrlField, this::currentIdentity, Identity::sessionCheckUrl);
        bindText(sessionValidRegexField, this::currentIdentity, Identity::sessionValidRegex);
        bindArea(staticHeadersArea, Identity::staticHeaders);
        // The compiled-script cache is keyed by source hash, so an edited script
        // never hits a stale class and the cache needs no explicit invalidation.
        bindArea(scriptArea, Identity::authScript);
        // Editing the script is what changes the credentials form, including
        // when the change arrives as a whole template or a loaded file.
        scriptArea.getDocument().addDocumentListener(new SimpleDocumentListener(paramsTimer::restart));

        bindText(refreshIntervalField, this::currentIdentity, (identity, value) -> {
            try {
                identity.refreshIntervalSeconds(Text.isBlank(value) ? 0L : Long.parseLong(value.trim()));
            } catch (NumberFormatException ignored) {
                // Leave the previous value until the tester finishes typing.
            }
        });

        enabledBox.addActionListener(e -> {
            Identity identity = currentIdentity();
            if (identity != null && !loading) {
                identity.enabled(enabledBox.isSelected());
                identityList.repaint();
                configuration.identitiesChanged();
            }
        });
        reauthOnDeniedBox.addActionListener(e -> {
            Identity identity = currentIdentity();
            if (identity != null && !loading) {
                identity.reauthOnDenied(reauthOnDeniedBox.isSelected());
                onFieldEdited();
            }
        });
    }

    private void bindText(JTextField field, Supplier<Identity> target,
            java.util.function.BiConsumer<Identity, String> setter) {
        field.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            Identity identity = target.get();
            if (identity != null && !loading) {
                setter.accept(identity, field.getText());
                onFieldEdited();
            }
        }));
    }

    private void bindArea(JTextArea area, java.util.function.BiConsumer<Identity, String> setter) {
        area.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            Identity identity = currentIdentity();
            if (identity != null && !loading) {
                setter.accept(identity, area.getText());
                onFieldEdited();
            }
        }));
    }

    /**
     * Re-reads the params block from the script in the editor and re-draws the
     * credentials form to match. Values already entered survive it, so this is
     * safe to run while the tester is still editing.
     */
    private void refreshDeclaredParams() {
        credentialsForm.setParams(ScriptParamExtractor.extract(scriptArea.getText()));
        Identity identity = currentIdentity();
        if (identity != null && !loading) {
            credentialsForm.applyTo(identity);
        }
    }

    /** Marks the model dirty and schedules a debounced project save. */
    private void onFieldEdited() {
        Identity identity = currentIdentity();
        if (identity != null && !loading) {
            credentialsForm.applyTo(identity);
            saveTimer.restart();
        }
    }

    private Identity currentIdentity() {
        return identityList.getSelectedValue();
    }

    // -- loading -------------------------------------------------------------

    private void reloadList() {
        Identity selected = identityList.getSelectedValue();
        listModel.clear();
        configuration.identities().forEach(listModel::addElement);
        if (selected != null && configuration.identities().contains(selected)) {
            identityList.setSelectedValue(selected, true);
        }
    }

    private void loadSelected() {
        Identity identity = currentIdentity();
        loading = true;
        try {
            if (identity == null) {
                clearFields();
                setFieldsEnabled(false);
                return;
            }
            setFieldsEnabled(true);
            nameField.setText(identity.name());
            enabledBox.setSelected(identity.enabled());
            notesField.setText(identity.notes());
            stripHeadersField.setText(identity.stripHeaders());
            staticHeadersArea.setText(identity.staticHeaders());
            tokenHeaderField.setText(identity.tokenHeaderName());
            refreshIntervalField.setText(String.valueOf(identity.refreshIntervalSeconds()));
            sessionInvalidRegexField.setText(identity.sessionInvalidRegex());
            reauthOnDeniedBox.setSelected(identity.reauthOnDenied());
            sessionCheckUrlField.setText(identity.sessionCheckUrl());
            sessionValidRegexField.setText(identity.sessionValidRegex());
            scriptArea.setText(identity.authScript());
            scriptArea.setCaretPosition(0);
            credentialsForm.setParams(ScriptParamExtractor.extract(identity.authScript()));
            credentialsForm.load(identity);
            refreshSessionStatus(identity);
            loadTranscript(identity);
        } finally {
            loading = false;
        }
    }

    private void clearFields() {
        nameField.setText("");
        notesField.setText("");
        stripHeadersField.setText("");
        staticHeadersArea.setText("");
        tokenHeaderField.setText("");
        refreshIntervalField.setText("0");
        sessionInvalidRegexField.setText("");
        sessionCheckUrlField.setText("");
        sessionValidRegexField.setText("");
        scriptArea.setText("");
        authLogArea.setText("");
        sessionStatusLabel.setText(" ");
        credentialsForm.load(null);
        loadTranscript(null);
    }

    private void setFieldsEnabled(boolean enabled) {
        for (JComponent field : new JComponent[] { nameField, enabledBox, notesField, stripHeadersField,
                staticHeadersArea, tokenHeaderField, refreshIntervalField, sessionInvalidRegexField,
                reauthOnDeniedBox, sessionCheckUrlField, sessionValidRegexField, scriptArea }) {
            field.setEnabled(enabled);
        }
        credentialsForm.setFormEnabled(enabled);
    }

    private void refreshSessionStatus(Identity identity) {
        sessionStatusLabel.setText("  " + sessionManager.statusFor(identity));
        String log = sessionManager.lastLogFor(identity);
        authLogArea.setText(log);
        authLogArea.setCaretPosition(0);
    }

    private void moveSelected(int delta) {
        int index = identityList.getSelectedIndex();
        int target = index + delta;
        if (index < 0 || target < 0 || target >= listModel.size()) {
            return;
        }
        Identity identity = listModel.get(index);
        configuration.move(index, target);
        reloadList();
        identityList.setSelectedValue(identity, true);
    }

    // -- actions -------------------------------------------------------------

    private void testAuthentication() {
        Identity identity = currentIdentity();
        if (identity == null) {
            return;
        }
        credentialsForm.applyTo(identity);
        configuration.save();
        sessionStatusLabel.setText("  Authenticating...");
        authLogArea.setText("");

        new SwingWorker<AuthOutcome, Void>() {
            @Override
            protected AuthOutcome doInBackground() {
                return sessionManager.authenticateNow(identity);
            }

            @Override
            protected void done() {
                try {
                    AuthOutcome outcome = get();
                    StringBuilder text = new StringBuilder();
                    if (outcome.success()) {
                        text.append("Authentication succeeded.\n\nAuth material applied to every replay:\n")
                                .append(outcome.material().describe());
                    } else {
                        text.append("Authentication FAILED.\n\n").append(outcome.error()).append('\n');
                    }
                    if (!Text.isBlank(outcome.log())) {
                        text.append("\nScript log:\n").append(outcome.log());
                    }
                    authLogArea.setText(text.toString());
                    authLogArea.setCaretPosition(0);
                    sessionStatusLabel.setText("  " + sessionManager.statusFor(identity));
                    loadTranscript(identity);
                } catch (Exception e) {
                    authLogArea.setText("Test failed: " + e);
                }
            }
        }.execute();
    }

    private boolean confirmOverwriteScript() {
        if (Text.isBlank(scriptArea.getText())) {
            return true;
        }
        return JOptionPane.showConfirmDialog(this, "Replace the current script with this template?",
                "Auth Check", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION;
    }

    private void loadScriptFromFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        if (!confirmOverwriteScript()) {
            return;
        }
        try {
            String body = Files.readString(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8);
            scriptArea.setText(body);
            scriptArea.setCaretPosition(0);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not read the file:\n" + e.getMessage(),
                    "Auth Check", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveScriptToFile() {
        Identity identity = currentIdentity();
        if (identity == null) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(
                identity.name().replaceAll("[^A-Za-z0-9._-]", "_") + ".groovy"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        try {
            Files.writeString(target, scriptArea.getText(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not write the file:\n" + e.getMessage(),
                    "Auth Check", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportIdentities() {
        List<Identity> identities = new ArrayList<>(configuration.identities());
        if (identities.isEmpty()) {
            JOptionPane.showMessageDialog(this, "There are no identities to export.",
                    "Auth Check", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        // Flush any in-progress edit before writing.
        Identity current = currentIdentity();
        if (current != null) {
            credentialsForm.applyTo(current);
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("auth-check-identities.json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        try {
            Files.writeString(target, IdentityTransfer.toJson(identities), StandardCharsets.UTF_8);
            JOptionPane.showMessageDialog(this,
                    "Exported " + identities.size() + " identit"
                    + (identities.size() == 1 ? "y" : "ies") + " to\n" + target
                    + "\n\nThis file contains credentials in clear text. Treat it as sensitive.",
                    "Auth Check", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not write the file:\n" + e.getMessage(),
                    "Auth Check", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importIdentities() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            String json = Files.readString(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8);
            List<Identity> imported = IdentityTransfer.fromJson(json);

            int choice = JOptionPane.showConfirmDialog(this,
                    "Add " + imported.size() + " identit" + (imported.size() == 1 ? "y" : "ies")
                    + " to this project? Existing identities are kept.",
                    "Auth Check", JOptionPane.OK_CANCEL_OPTION);
            if (choice != JOptionPane.OK_OPTION) {
                return;
            }

            imported.forEach(configuration.identities()::add);
            configuration.identitiesChanged();
            reloadList();
            identityList.setSelectedValue(imported.get(0), true);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Could not read the file:\n" + e.getMessage(),
                    "Auth Check", JOptionPane.ERROR_MESSAGE);
        } catch (RuntimeException e) {
            JOptionPane.showMessageDialog(this, "That file could not be imported:\n" + e.getMessage(),
                    "Auth Check", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showLongMessage(String title, String body) {
        JTextArea area = UiUtils.codeArea(api, 14, 80);
        area.setText(body);
        area.setEditable(false);
        area.setCaretPosition(0);
        JOptionPane.showMessageDialog(this, new JScrollPane(area), title, JOptionPane.ERROR_MESSAGE);
    }

    /** Called when the tab becomes visible so session status is not stale. */
    public void refreshStatus() {
        Identity identity = currentIdentity();
        if (identity != null) {
            SwingUtilities.invokeLater(() -> refreshSessionStatus(identity));
        }
    }

    /** Shows name plus whether the identity is in play. */
    private static final class IdentityRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof Identity identity) {
                setText(identity.enabled() ? identity.name() : identity.name() + "  (disabled)");
                setEnabled(identity.enabled());
            }
            return this;
        }
    }

    /** Fires one callback for any document change. */
    private record SimpleDocumentListener(Runnable onChange) implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent event) {
            onChange.run();
        }

        @Override
        public void removeUpdate(DocumentEvent event) {
            onChange.run();
        }

        @Override
        public void changedUpdate(DocumentEvent event) {
            onChange.run();
        }
    }
}
