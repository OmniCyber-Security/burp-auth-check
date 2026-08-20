package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.MontoyaApi;
import com.omnicybersecurity.authcheck.auth.ScriptParam;
import com.omnicybersecurity.authcheck.auth.ScriptParams;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.util.Text;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The credentials editor: a typed form for whatever the identity's script
 * declares, and the free-form name/value table for everything else.
 *
 * <p>Which one a tester sees is decided by the script, not by a setting. A
 * script with a {@code params} block produces labelled fields, masked secrets,
 * drop-downs and inline validation; a script without one produces the table it
 * always did.
 *
 * <p>Values are never thrown away when the script changes. Switching templates
 * re-draws the form, but a password typed against the old script is still in the
 * identity, and turns up either in the new form or in the table underneath it.
 * The alternative -- clearing what is no longer declared -- would silently
 * destroy credentials on a keystroke in the editor.
 */
public final class CredentialsForm extends JPanel {

    /** Readable against both Burp themes, which a plain Color.RED is not. */
    private static final Color PROBLEM = new Color(0xD9, 0x53, 0x4F);

    private final MontoyaApi api;
    private final Runnable onChanged;

    private final JPanel content = new JPanel(new BorderLayout());
    private final JPanel declaredFields = new JPanel(new GridBagLayout());
    private final JScrollPane declaredScroll = new JScrollPane(declaredFields);
    private final JPanel declaredSection = new JPanel(new BorderLayout());
    private final JPanel extrasSection = new JPanel(new BorderLayout());
    private final JLabel problemsLabel = new JLabel(" ");

    private final CredentialsTableModel extrasModel;
    private final JTable extrasTable;
    private final JCheckBox showValuesBox = new JCheckBox("Show values");

    private final Map<String, ParamField> fields = new LinkedHashMap<>();
    private ScriptParams params = ScriptParams.none();

    /** Suppresses change events while the form is being built or populated. */
    private boolean populating;

    public CredentialsForm(MontoyaApi api, Runnable onChanged) {
        super(new BorderLayout());
        this.api = api;
        this.onChanged = onChanged;
        this.extrasModel = new CredentialsTableModel(this::changed);
        this.extrasTable = new JTable(extrasModel);

        extrasTable.setPreferredScrollableViewportSize(new Dimension(420, 110));
        extrasTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        declaredScroll.setBorder(BorderFactory.createEmptyBorder());
        problemsLabel.setForeground(PROBLEM);
        problemsLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 4, 8));

        buildExtrasSection();
        declaredSection.add(declaredScroll, BorderLayout.CENTER);

        add(content, BorderLayout.CENTER);
        add(problemsLabel, BorderLayout.SOUTH);
        layoutSections();
    }

    private void buildExtrasSection() {
        JToolBar buttons = new JToolBar();
        buttons.setFloatable(false);
        JButton add = new JButton("Add");
        add.addActionListener(e -> extrasModel.addRow());
        buttons.add(add);
        JButton remove = new JButton("Remove");
        remove.addActionListener(e -> extrasModel.removeRow(extrasTable.getSelectedRow()));
        buttons.add(remove);
        buttons.add(showValuesBox);
        showValuesBox.addActionListener(e -> setShowValues(showValuesBox.isSelected()));

        extrasSection.add(new JScrollPane(extrasTable), BorderLayout.CENTER);
        extrasSection.add(buttons, BorderLayout.SOUTH);
    }

    /** Reveals both the masked table cells and the declared secret fields. */
    private void setShowValues(boolean show) {
        extrasModel.setShowValues(show);
        fields.values().forEach(field -> field.showSecret(show));
    }

    // -- what the script declares --------------------------------------------

    /**
     * Re-draws the form for a script's declarations. Called as the tester edits
     * the script, so it keeps whatever is already typed into fields that are
     * still declared.
     */
    public void setParams(ScriptParams declared) {
        if (declared.equals(params)) {
            return;
        }
        Map<String, String> current = declaredValues();
        params = declared;
        rebuildFields();
        populating = true;
        try {
            current.forEach((name, value) -> {
                ParamField field = fields.get(name);
                if (field != null) {
                    field.value(value);
                } else if (!Text.isBlank(value)) {
                    // The script stopped declaring this one. It is still a
                    // credential of this identity, and a password must not
                    // evaporate because someone edited the script above it.
                    extrasModel.put(name, value);
                }
            });
        } finally {
            populating = false;
        }
        layoutSections();
        refreshProblems();
    }

    private void rebuildFields() {
        fields.clear();
        declaredFields.removeAll();
        int row = 0;
        boolean anyRequired = false;

        for (ScriptParam param : params.params()) {
            ParamField field = fieldFor(param);
            fields.put(param.name(), field);
            anyRequired |= param.required();

            JLabel label = new JLabel(param.displayLabel() + (param.required() ? " *" : ""));
            if (param.required()) {
                label.setFont(label.getFont().deriveFont(Font.BOLD));
            }
            String tooltip = "Read by the script as creds." + param.name();
            label.setToolTipText(tooltip);
            field.component().setToolTipText(tooltip);

            declaredFields.add(label, labelConstraints(row));
            declaredFields.add(field.component(), fieldConstraints(row));
            row++;

            String hint = hintFor(param);
            if (!hint.isEmpty()) {
                declaredFields.add(UiUtils.hint(hint), hintConstraints(row));
                row++;
            }
        }

        if (anyRequired) {
            declaredFields.add(UiUtils.hint("Fields marked * are required; the rest are optional."),
                    hintConstraints(row));
            row++;
        }

        GridBagConstraints filler = new GridBagConstraints();
        filler.gridx = 0;
        filler.gridy = row;
        filler.gridwidth = 2;
        filler.weighty = 1;
        filler.fill = GridBagConstraints.BOTH;
        declaredFields.add(new JPanel(), filler);

        setShowValues(showValuesBox.isSelected());
        declaredFields.revalidate();
        declaredFields.repaint();
    }

    /** What the field says under itself: why it exists, and what it falls back to. */
    private static String hintFor(ScriptParam param) {
        List<String> parts = new ArrayList<>();
        if (!param.help().isEmpty()) {
            parts.add(param.help());
        }
        if (param.hasDefault()) {
            parts.add("Leave empty to use " + param.defaultValue());
        }
        return String.join("  ·  ", parts);
    }

    private ParamField fieldFor(ScriptParam param) {
        return switch (param.type()) {
            case SECRET -> new SecretField();
            case BOOL -> new BoolField();
            case CHOICE -> new ChoiceField(param);
            case TEXT -> new AreaField(api);
            case INT -> new TextParamField(new JTextField(12));
            case STRING, URL -> new TextParamField(new JTextField(30));
        };
    }

    /**
     * Shows the declared form over the leftovers, or just the table when the
     * script declares nothing.
     */
    private void layoutSections() {
        content.removeAll();
        if (params.hasFields()) {
            declaredSection.setBorder(BorderFactory.createTitledBorder(
                    "Credential variables declared by this script"));
            extrasSection.setBorder(BorderFactory.createTitledBorder(
                    "Other credentials -- not declared by this script, read as creds.<name>"));
            extrasTable.setPreferredScrollableViewportSize(new Dimension(420, 80));
            content.add(declaredSection, BorderLayout.CENTER);
            content.add(extrasSection, BorderLayout.SOUTH);
        } else {
            extrasSection.setBorder(BorderFactory.createTitledBorder(
                    "Credential variables -- read by scripts as creds.<name>, saved in the Burp project"));
            extrasTable.setPreferredScrollableViewportSize(new Dimension(420, 140));
            content.add(extrasSection, BorderLayout.CENTER);
        }
        revalidate();
        repaint();
    }

    // -- reading and writing the identity ------------------------------------

    public void load(Identity identity) {
        populating = true;
        try {
            Map<String, String> credentials = identity == null
                    ? Map.of() : identity.credentialsSnapshot();
            fields.forEach((name, field) -> field.value(Text.nullToEmpty(credentials.get(name))));
            extrasModel.load(identity, fields.keySet());
        } finally {
            populating = false;
        }
        refreshProblems();
    }

    /**
     * Writes the form back onto the identity: declared fields first, in the
     * order the script declares them, then anything left in the table.
     *
     * <p>A blank declared field is not stored. It carries no information -- the
     * script's own default or its required check covers it -- and storing one
     * would leave an empty row behind in the table the moment the script stopped
     * declaring it.
     */
    public void applyTo(Identity identity) {
        if (identity == null) {
            return;
        }
        Map<String, String> updated = new LinkedHashMap<>();
        fields.forEach((name, field) -> {
            String value = field.value();
            if (!Text.isBlank(value)) {
                updated.put(name, value);
            }
        });
        extrasModel.values().forEach(updated::putIfAbsent);

        synchronized (identity.credentials()) {
            identity.credentials().clear();
            identity.credentials().putAll(updated);
        }
    }

    private Map<String, String> declaredValues() {
        Map<String, String> values = new LinkedHashMap<>();
        fields.forEach((name, field) -> values.put(name, field.value()));
        return values;
    }

    public void setFormEnabled(boolean enabled) {
        extrasTable.setEnabled(enabled);
        showValuesBox.setEnabled(enabled);
        fields.values().forEach(field -> field.setFieldEnabled(enabled));
    }

    // -- validation ----------------------------------------------------------

    /**
     * Says what is still wrong before the tester presses "Test authentication
     * now" -- the same checks the engine refuses the run with, so the message
     * cannot disagree with what happens.
     */
    private void refreshProblems() {
        if (!params.hasFields() && params.problems().isEmpty()) {
            problemsLabel.setText(" ");
            return;
        }
        if (!params.problems().isEmpty()) {
            problemsLabel.setText("This script's params block is not valid: " + params.problems().get(0));
            return;
        }
        Map<String, String> values = declaredValues();
        List<String> missing = params.missingRequired(values);
        List<String> invalid = params.valueProblems(values);
        if (!missing.isEmpty()) {
            problemsLabel.setText("Still needed: " + String.join(", ", missing));
        } else if (!invalid.isEmpty()) {
            problemsLabel.setText(String.join("; ", invalid));
        } else {
            problemsLabel.setText(" ");
        }
    }

    private void changed() {
        if (populating) {
            return;
        }
        refreshProblems();
        onChanged.run();
    }

    // -- the widgets ---------------------------------------------------------

    private interface ParamField {
        JComponent component();

        String value();

        void value(String value);

        void setFieldEnabled(boolean enabled);

        /** Only a secret field has anything to reveal. */
        default void showSecret(boolean show) {
        }
    }

    /** Fires {@link #changed()} for any edit to a text component. */
    private final class EditListener implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent event) {
            changed();
        }

        @Override
        public void removeUpdate(DocumentEvent event) {
            changed();
        }

        @Override
        public void changedUpdate(DocumentEvent event) {
            changed();
        }
    }

    private class TextParamField implements ParamField {
        private final JTextComponent field;
        private final JComponent view;

        TextParamField(JTextComponent field) {
            this(field, field);
        }

        TextParamField(JTextComponent field, JComponent view) {
            this.field = field;
            this.view = view;
            field.getDocument().addDocumentListener(new EditListener());
        }

        @Override
        public JComponent component() {
            return view;
        }

        @Override
        public String value() {
            return field.getText();
        }

        @Override
        public void value(String value) {
            field.setText(Text.nullToEmpty(value));
        }

        @Override
        public void setFieldEnabled(boolean enabled) {
            field.setEnabled(enabled);
        }
    }

    private final class SecretField extends TextParamField {
        private final JPasswordField password;
        private final char echoChar;

        SecretField() {
            this(new JPasswordField(30));
        }

        private SecretField(JPasswordField password) {
            super(password);
            this.password = password;
            this.echoChar = password.getEchoChar();
        }

        @Override
        public String value() {
            return new String(password.getPassword());
        }

        @Override
        public void showSecret(boolean show) {
            password.setEchoChar(show ? (char) 0 : echoChar);
        }
    }

    private final class AreaField extends TextParamField {
        AreaField(MontoyaApi api) {
            this(UiUtils.codeArea(api, 4, 40));
        }

        private AreaField(JTextArea area) {
            super(area, new JScrollPane(area));
        }
    }

    private final class BoolField implements ParamField {
        private final JCheckBox box = new JCheckBox();

        BoolField() {
            box.addActionListener(e -> changed());
        }

        @Override
        public JComponent component() {
            return box;
        }

        @Override
        public String value() {
            return box.isSelected() ? "true" : "false";
        }

        @Override
        public void value(String value) {
            box.setSelected("true".equalsIgnoreCase(Text.nullToEmpty(value).trim()));
        }

        @Override
        public void setFieldEnabled(boolean enabled) {
            box.setEnabled(enabled);
        }
    }

    private final class ChoiceField implements ParamField {
        private final JComboBox<String> combo = new JComboBox<>();

        ChoiceField(ScriptParam param) {
            // An optional choice needs a way back to "not set"; a required one
            // must not start on a value nobody chose.
            combo.addItem("");
            param.choices().forEach(combo::addItem);
            combo.addActionListener(e -> changed());
        }

        @Override
        public JComponent component() {
            return combo;
        }

        @Override
        public String value() {
            Object selected = combo.getSelectedItem();
            return selected == null ? "" : selected.toString();
        }

        @Override
        public void value(String value) {
            combo.setSelectedItem(Text.nullToEmpty(value));
        }

        @Override
        public void setFieldEnabled(boolean enabled) {
            combo.setEnabled(enabled);
        }
    }

    // -- layout helpers ------------------------------------------------------

    private static GridBagConstraints labelConstraints(int row) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = row;
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.insets = new Insets(5, 4, 1, 8);
        return constraints;
    }

    private static GridBagConstraints fieldConstraints(int row) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 1;
        constraints.gridy = row;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(3, 0, 1, 6);
        return constraints;
    }

    private static GridBagConstraints hintConstraints(int row) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 1;
        constraints.gridy = row;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(0, 0, 5, 6);
        return constraints;
    }
}
