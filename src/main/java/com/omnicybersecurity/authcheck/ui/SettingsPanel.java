package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.core.ToolType;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.util.Patterns;
import com.omnicybersecurity.authcheck.util.Text;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** The Settings tab: what gets tested, and how responses are judged. */
public final class SettingsPanel extends JPanel {

    private final Configuration configuration;

    private final JCheckBox autoTestEnabled = new JCheckBox("Automatically test traffic as it arrives");
    private final JCheckBox testUnauthenticated = new JCheckBox("Also replay every request with no credentials");
    private final JCheckBox onlyInScope = new JCheckBox("Only test URLs in Burp's target scope");
    private final JCheckBox dedupeRequests = new JCheckBox("Test each endpoint only once");
    private final JCheckBox dedupeIncludesParamNames =
            new JCheckBox("Treat a different set of parameter names as a different endpoint");
    private final JCheckBox skipStaticResources = new JCheckBox("Skip static resources");
    private final JCheckBox useBurpVariationsAnalyzer =
            new JCheckBox("Compare with Burp's response-variations analyser instead of body similarity");
    private final JCheckBox followRedirectsOnReplay = new JCheckBox("Follow redirects when replaying");
    private final JCheckBox treatLoginRedirectAsEnforced =
            new JCheckBox("Treat a redirect to a login URL as enforcement");
    private final JCheckBox persistResults =
            new JCheckBox("Store tested requests and responses in the Burp project");
    private final JCheckBox persistOnlyInteresting =
            new JCheckBox("Store only rows worth revisiting (bypassed, review, auth failed)");

    private final Map<ToolType, JCheckBox> toolBoxes = new LinkedHashMap<>();

    private final JTextField skipExtensions = new JTextField(48);
    private final JTextField skipStatusCodes = new JTextField(24);
    private final JTextField includeUrlRegex = new JTextField(48);
    private final JTextField excludeUrlRegex = new JTextField(48);
    private final JTextField threadCount = new JTextField(6);
    private final JTextField queueCapacity = new JTextField(6);
    private final JTextField responseTimeoutMillis = new JTextField(8);
    private final JTextField maxRecords = new JTextField(8);
    private final JTextField scriptTimeoutSeconds = new JTextField(6);
    private final JTextField sameThresholdPercent = new JTextField(6);
    private final JTextField maxCompareBytes = new JTextField(10);
    private final JTextField deniedStatusCodes = new JTextField(24);
    private final JTextField deniedBodyRegex = new JTextField(64);
    private final JTextField loginRedirectRegex = new JTextField(64);
    private final JTextField unauthStripHeaders = new JTextField(64);
    private final JTextField maxPersistedRecords = new JTextField(8);

    public SettingsPanel(Configuration configuration) {
        super(new BorderLayout());
        this.configuration = configuration;

        add(buildToolBar(), BorderLayout.NORTH);
        add(UiUtils.scroll(buildForm()), BorderLayout.CENTER);
        load();

        configuration.onSettingsChanged(() -> {
            // Keep the checkbox in step when the Results toolbar toggles it.
            autoTestEnabled.setSelected(configuration.settings().autoTestEnabled());
        });
    }

    private JComponent buildToolBar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        JButton apply = new JButton("Apply");
        apply.addActionListener(e -> apply());
        bar.add(apply);
        JButton reload = new JButton("Revert");
        reload.addActionListener(e -> load());
        bar.add(reload);
        JButton defaults = new JButton("Restore defaults");
        defaults.addActionListener(e -> restoreDefaults());
        bar.add(defaults);
        bar.addSeparator();
        bar.add(UiUtils.hint("Changes take effect when you press Apply."));
        return bar;
    }

    private JComponent buildForm() {
        UiUtils.Form form = new UiUtils.Form();

        form.addWide(UiUtils.title("What gets tested"));
        form.addWide(autoTestEnabled);
        form.addWide(testUnauthenticated);
        form.addWide(onlyInScope);
        form.add("Test traffic from:", buildToolSelector());
        form.addWide(dedupeRequests);
        form.addWide(dedupeIncludesParamNames);
        form.addWide(skipStaticResources);
        form.add("Skip these file extensions:", skipExtensions);
        form.add("Skip these baseline statuses:", skipStatusCodes);
        form.add("Only URLs matching (regex):", includeUrlRegex);
        form.add("Never URLs matching (regex):", excludeUrlRegex);
        form.addWide(UiUtils.hint(
                "Right-click any request and choose \"Send to Auth Check\" to test it regardless of these filters."));

        form.addWide(UiUtils.title("Judging the responses"));
        form.addWide(UiUtils.hint(
                "A bypass is reported when a replay returns the same status and near-identical body to the baseline "
                + "-- and only when the baseline itself was a 2xx, since nothing else proves what access looks like."));
        form.add("Same-response threshold (%):", sameThresholdPercent);
        form.add("Compare at most (bytes):", maxCompareBytes);
        form.addWide(useBurpVariationsAnalyzer);
        form.addWide(followRedirectsOnReplay);
        form.addWide(UiUtils.hint(
                "Leave redirect-following off so a 302 to /login is visible as enforcement rather than followed."));

        form.addWide(UiUtils.title("What counts as \"access denied\""));
        form.add("Denied status codes:", deniedStatusCodes);
        form.add("Denied body pattern (regex):", deniedBodyRegex);
        form.addWide(treatLoginRedirectAsEnforced);
        form.add("Login URL pattern (regex):", loginRedirectRegex);

        form.addWide(UiUtils.title("Unauthenticated replay"));
        form.add("Strip these headers:", unauthStripHeaders);

        form.addWide(UiUtils.title("Storing results in the project"));
        form.addWide(UiUtils.hint(
                "Results are written into the Burp project file, next to the identities and their auth scripts, "
                + "so reopening the project brings back the evidence as well as the configuration. The traffic "
                + "each auth script generated while logging in is stored with it."));
        form.addWide(persistResults);
        form.addWide(persistOnlyInteresting);
        form.add("Store at most N results:", maxPersistedRecords);
        form.addWide(UiUtils.hint(
                "Each stored result holds the baseline exchange plus one per identity, so this is the main "
                + "influence on how much the extension adds to the project file. 0 stores none."));

        form.addWide(UiUtils.title("Performance"));
        form.add("Worker threads:", threadCount);
        form.add("Queue capacity (needs reload):", queueCapacity);
        form.add("Response timeout (ms):", responseTimeoutMillis);
        form.add("Auth script timeout (s):", scriptTimeoutSeconds);
        form.add("Keep at most N results:", maxRecords);
        form.addFiller();
        return form.panel();
    }

    private JComponent buildToolSelector() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        panel.setBorder(BorderFactory.createEmptyBorder());
        for (ToolType tool : Settings.SELECTABLE_TOOLS) {
            JCheckBox box = new JCheckBox(tool.toolName());
            toolBoxes.put(tool, box);
            panel.add(box);
        }
        return panel;
    }

    // -- load / apply --------------------------------------------------------

    private void load() {
        Settings settings = configuration.settings();
        autoTestEnabled.setSelected(settings.autoTestEnabled());
        testUnauthenticated.setSelected(settings.testUnauthenticated());
        onlyInScope.setSelected(settings.onlyInScope());
        dedupeRequests.setSelected(settings.dedupeRequests());
        dedupeIncludesParamNames.setSelected(settings.dedupeIncludesParamNames());
        skipStaticResources.setSelected(settings.skipStaticResources());
        useBurpVariationsAnalyzer.setSelected(settings.useBurpVariationsAnalyzer());
        followRedirectsOnReplay.setSelected(settings.followRedirectsOnReplay());
        treatLoginRedirectAsEnforced.setSelected(settings.treatLoginRedirectAsEnforced());
        persistResults.setSelected(settings.persistResults());
        persistOnlyInteresting.setSelected(settings.persistOnlyInteresting());
        maxPersistedRecords.setText(String.valueOf(settings.maxPersistedRecords()));

        toolBoxes.forEach((tool, box) -> box.setSelected(settings.sourceTools().contains(tool)));

        skipExtensions.setText(settings.skipExtensions());
        skipStatusCodes.setText(settings.skipStatusCodes());
        includeUrlRegex.setText(settings.includeUrlRegex());
        excludeUrlRegex.setText(settings.excludeUrlRegex());
        threadCount.setText(String.valueOf(settings.threadCount()));
        queueCapacity.setText(String.valueOf(settings.queueCapacity()));
        responseTimeoutMillis.setText(String.valueOf(settings.responseTimeoutMillis()));
        maxRecords.setText(String.valueOf(settings.maxRecords()));
        scriptTimeoutSeconds.setText(String.valueOf(settings.scriptTimeoutSeconds()));
        sameThresholdPercent.setText(String.valueOf(settings.sameThresholdPercent()));
        maxCompareBytes.setText(String.valueOf(settings.maxCompareBytes()));
        deniedStatusCodes.setText(settings.deniedStatusCodes());
        deniedBodyRegex.setText(settings.deniedBodyRegex());
        loginRedirectRegex.setText(settings.loginRedirectRegex());
        unauthStripHeaders.setText(settings.unauthStripHeaders());
    }

    private void apply() {
        String error = validateFields();
        if (error != null) {
            JOptionPane.showMessageDialog(this, error, "Auth Check", JOptionPane.ERROR_MESSAGE);
            return;
        }
        Settings settings = configuration.settings();
        settings.autoTestEnabled(autoTestEnabled.isSelected());
        settings.testUnauthenticated(testUnauthenticated.isSelected());
        settings.onlyInScope(onlyInScope.isSelected());
        settings.dedupeRequests(dedupeRequests.isSelected());
        settings.dedupeIncludesParamNames(dedupeIncludesParamNames.isSelected());
        settings.skipStaticResources(skipStaticResources.isSelected());
        settings.useBurpVariationsAnalyzer(useBurpVariationsAnalyzer.isSelected());
        settings.followRedirectsOnReplay(followRedirectsOnReplay.isSelected());
        settings.treatLoginRedirectAsEnforced(treatLoginRedirectAsEnforced.isSelected());
        settings.persistResults(persistResults.isSelected());
        settings.persistOnlyInteresting(persistOnlyInteresting.isSelected());

        Set<ToolType> tools = EnumSet.noneOf(ToolType.class);
        toolBoxes.forEach((tool, box) -> {
            if (box.isSelected()) {
                tools.add(tool);
            }
        });
        settings.sourceTools(tools);

        settings.skipExtensions(skipExtensions.getText());
        settings.skipStatusCodes(skipStatusCodes.getText());
        settings.includeUrlRegex(includeUrlRegex.getText());
        settings.excludeUrlRegex(excludeUrlRegex.getText());
        settings.deniedStatusCodes(deniedStatusCodes.getText());
        settings.deniedBodyRegex(deniedBodyRegex.getText());
        settings.loginRedirectRegex(loginRedirectRegex.getText());
        settings.unauthStripHeaders(unauthStripHeaders.getText());

        settings.threadCount(parseInt(threadCount.getText(), settings.threadCount()));
        settings.queueCapacity(parseInt(queueCapacity.getText(), settings.queueCapacity()));
        settings.responseTimeoutMillis(parseLong(responseTimeoutMillis.getText(), settings.responseTimeoutMillis()));
        settings.maxRecords(parseInt(maxRecords.getText(), settings.maxRecords()));
        settings.scriptTimeoutSeconds(parseInt(scriptTimeoutSeconds.getText(), settings.scriptTimeoutSeconds()));
        settings.sameThresholdPercent(parseInt(sameThresholdPercent.getText(), settings.sameThresholdPercent()));
        settings.maxCompareBytes(parseInt(maxCompareBytes.getText(), settings.maxCompareBytes()));
        settings.maxPersistedRecords(parseInt(maxPersistedRecords.getText(), settings.maxPersistedRecords()));

        configuration.settingsChanged();
        // Re-read so clamped values are visible rather than silently corrected.
        load();
    }

    private void restoreDefaults() {
        int choice = JOptionPane.showConfirmDialog(this,
                "Reset all settings to their defaults? Identities and credentials are not affected.",
                "Auth Check", JOptionPane.OK_CANCEL_OPTION);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }
        Settings defaults = new Settings();
        Settings settings = configuration.settings();
        settings.autoTestEnabled(defaults.autoTestEnabled());
        settings.testUnauthenticated(defaults.testUnauthenticated());
        settings.onlyInScope(defaults.onlyInScope());
        settings.dedupeRequests(defaults.dedupeRequests());
        settings.dedupeIncludesParamNames(defaults.dedupeIncludesParamNames());
        settings.skipStaticResources(defaults.skipStaticResources());
        settings.useBurpVariationsAnalyzer(defaults.useBurpVariationsAnalyzer());
        settings.followRedirectsOnReplay(defaults.followRedirectsOnReplay());
        settings.treatLoginRedirectAsEnforced(defaults.treatLoginRedirectAsEnforced());
        settings.persistResults(defaults.persistResults());
        settings.persistOnlyInteresting(defaults.persistOnlyInteresting());
        settings.maxPersistedRecords(defaults.maxPersistedRecords());
        settings.sourceTools(defaults.sourceTools());
        settings.skipExtensions(defaults.skipExtensions());
        settings.skipStatusCodes(defaults.skipStatusCodes());
        settings.includeUrlRegex(defaults.includeUrlRegex());
        settings.excludeUrlRegex(defaults.excludeUrlRegex());
        settings.deniedStatusCodes(defaults.deniedStatusCodes());
        settings.deniedBodyRegex(defaults.deniedBodyRegex());
        settings.loginRedirectRegex(defaults.loginRedirectRegex());
        settings.unauthStripHeaders(defaults.unauthStripHeaders());
        settings.threadCount(defaults.threadCount());
        settings.queueCapacity(defaults.queueCapacity());
        settings.responseTimeoutMillis(defaults.responseTimeoutMillis());
        settings.maxRecords(defaults.maxRecords());
        settings.scriptTimeoutSeconds(defaults.scriptTimeoutSeconds());
        settings.sameThresholdPercent(defaults.sameThresholdPercent());
        settings.maxCompareBytes(defaults.maxCompareBytes());
        configuration.settingsChanged();
        load();
    }

    /** Returns a message describing the first invalid field, or null. */
    private String validateFields() {
        Map<String, String> regexes = new LinkedHashMap<>();
        regexes.put("Only URLs matching", includeUrlRegex.getText());
        regexes.put("Never URLs matching", excludeUrlRegex.getText());
        regexes.put("Denied body pattern", deniedBodyRegex.getText());
        regexes.put("Login URL pattern", loginRedirectRegex.getText());
        for (Map.Entry<String, String> entry : regexes.entrySet()) {
            String problem = Patterns.validationError(entry.getValue());
            if (problem != null) {
                return "The \"" + entry.getKey() + "\" regex is not valid:\n" + problem;
            }
        }
        if (Text.splitInts(deniedStatusCodes.getText()).isEmpty() && !Text.isBlank(deniedStatusCodes.getText())) {
            return "Denied status codes must be a comma-separated list of numbers.";
        }
        return null;
    }

    private static int parseInt(String text, int fallback) {
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static long parseLong(String text, long fallback) {
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
