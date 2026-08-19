package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;
import com.omnicybersecurity.authcheck.model.Verdict;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/** Shared Swing helpers: verdict colours, monospaced editors, simple forms. */
public final class UiUtils {

    private UiUtils() {
    }

    public static boolean isDark(MontoyaApi api) {
        try {
            return api.userInterface().currentTheme() == Theme.DARK;
        } catch (Exception e) {
            return false;
        }
    }

    /** Background colour for a verdict cell, tuned for the active Burp theme. */
    public static Color verdictBackground(Verdict verdict, boolean dark) {
        if (verdict == null) {
            return null;
        }
        return switch (verdict) {
            case BYPASSED -> dark ? new Color(122, 32, 32) : new Color(255, 186, 186);
            case NEEDS_REVIEW -> dark ? new Color(122, 92, 20) : new Color(255, 231, 170);
            case ENFORCED -> dark ? new Color(31, 82, 41) : new Color(198, 239, 206);
            case AUTH_FAILED -> dark ? new Color(96, 60, 110) : new Color(226, 205, 240);
            case ERROR -> dark ? new Color(80, 80, 80) : new Color(220, 220, 220);
            case NOT_TESTED -> null;
        };
    }

    public static Color verdictForeground(Verdict verdict, boolean dark) {
        if (verdict == null || verdict == Verdict.NOT_TESTED) {
            return null;
        }
        return dark ? Color.WHITE : Color.BLACK;
    }

    public static Font monospaced(MontoyaApi api) {
        try {
            Font editorFont = api.userInterface().currentEditorFont();
            if (editorFont != null) {
                return editorFont;
            }
        } catch (Exception ignored) {
            // Fall through to a platform monospaced font.
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    public static JTextArea codeArea(MontoyaApi api, int rows, int columns) {
        JTextArea area = new JTextArea(rows, columns);
        area.setFont(monospaced(api));
        area.setLineWrap(false);
        area.setTabSize(4);
        return area;
    }

    public static JScrollPane scroll(JComponent component) {
        JScrollPane pane = new JScrollPane(component);
        pane.setBorder(BorderFactory.createEmptyBorder());
        return pane;
    }

    public static JLabel hint(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.ITALIC, label.getFont().getSize() - 1f));
        return label;
    }

    public static JLabel title(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize() + 2f));
        return label;
    }

    /** Minimal two-column form builder over GridBagLayout. */
    public static final class Form {
        private final JPanel panel = new JPanel(new GridBagLayout());
        private int row;

        public Form() {
            panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        }

        public Form add(String label, JComponent field) {
            return add(label, field, false);
        }

        /** Adds a row; {@code stretchVertically} gives the field the spare height. */
        public Form add(String label, JComponent field, boolean stretchVertically) {
            GridBagConstraints labelConstraints = new GridBagConstraints();
            labelConstraints.gridx = 0;
            labelConstraints.gridy = row;
            labelConstraints.anchor = GridBagConstraints.NORTHWEST;
            labelConstraints.insets = new Insets(4, 4, 4, 8);
            panel.add(new JLabel(label), labelConstraints);

            GridBagConstraints fieldConstraints = new GridBagConstraints();
            fieldConstraints.gridx = 1;
            fieldConstraints.gridy = row;
            fieldConstraints.weightx = 1;
            fieldConstraints.weighty = stretchVertically ? 1 : 0;
            fieldConstraints.fill = stretchVertically
                    ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
            fieldConstraints.anchor = GridBagConstraints.WEST;
            fieldConstraints.insets = new Insets(4, 0, 4, 4);
            panel.add(field, fieldConstraints);

            row++;
            return this;
        }

        /** Adds a component spanning both columns. */
        public Form addWide(JComponent component) {
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.gridx = 0;
            constraints.gridy = row++;
            constraints.gridwidth = 2;
            constraints.weightx = 1;
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.anchor = GridBagConstraints.WEST;
            constraints.insets = new Insets(8, 4, 4, 4);
            panel.add(component, constraints);
            return this;
        }

        /** Pushes everything above it to the top of the container. */
        public Form addFiller() {
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.gridx = 0;
            constraints.gridy = row++;
            constraints.gridwidth = 2;
            constraints.weighty = 1;
            constraints.fill = GridBagConstraints.BOTH;
            panel.add(new JPanel(), constraints);
            return this;
        }

        public JPanel panel() {
            return panel;
        }
    }
}
