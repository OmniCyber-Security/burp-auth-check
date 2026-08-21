package com.omnicybersecurity.authcheck.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;
import com.omnicybersecurity.authcheck.model.Verdict;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/** Shared Swing helpers: verdict colours, monospaced editors, simple forms. */
public final class UiUtils {

    private UiUtils() {
    }

    /**
     * The window a dialog raised from {@code component} should belong to.
     *
     * <p>Burp resolves this itself, which keeps a dialog on the monitor holding
     * the window the user clicked in -- including a tab that has been detached
     * into its own frame. The suite frame is the fallback for the case where the
     * component is not in a hierarchy yet, so a dialog is never parentless and
     * never lands on the wrong screen.
     */
    public static Window dialogParent(MontoyaApi api, Component component) {
        try {
            if (component != null) {
                Window window = api.userInterface().swingUtils().windowForComponent(component);
                if (window != null) {
                    return window;
                }
            }
            return api.userInterface().swingUtils().suiteFrame();
        } catch (Exception e) {
            // Never let dialog parenting be the thing that breaks the UI.
            return null;
        }
    }

    /** Shows an informational dialog parented to Burp's window. */
    public static void info(MontoyaApi api, Component owner, String message) {
        JOptionPane.showMessageDialog(dialogParent(api, owner), message,
                "Auth Check", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * The most useful single line about a failure. {@code getMessage()} is null
     * for plenty of exceptions -- {@code NullPointerException} among them -- and
     * "Could not write the file: null" tells the tester nothing.
     */
    public static String describe(Throwable error) {
        if (error == null) {
            return "unknown error";
        }
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.toString() : message;
    }

    /** Shows an error dialog parented to Burp's window. */
    public static void error(MontoyaApi api, Component owner, String message) {
        JOptionPane.showMessageDialog(dialogParent(api, owner), message,
                "Auth Check", JOptionPane.ERROR_MESSAGE);
    }

    /** Asks for confirmation, parented to Burp's window. True when confirmed. */
    public static boolean confirm(MontoyaApi api, Component owner, String message) {
        return JOptionPane.showConfirmDialog(dialogParent(api, owner), message,
                "Auth Check", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION;
    }

    /**
     * Runs {@code work} off the event thread and hands the result back on it.
     *
     * <p>Anything that touches the disk, the network or the Groovy compiler goes
     * through here: on the event thread it would freeze the whole of Burp, not
     * just this tab. Failures are delivered to {@code onFailure} rather than
     * vanishing, because Burp does not report exceptions thrown on threads it
     * does not own.
     */
    public static <T> void inBackground(Callable<T> work, Consumer<T> onSuccess, Consumer<Throwable> onFailure) {
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return work.call();
            }

            @Override
            protected void done() {
                try {
                    onSuccess.accept(get());
                } catch (java.util.concurrent.ExecutionException e) {
                    onFailure.accept(e.getCause() == null ? e : e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    onFailure.accept(e);
                } catch (RuntimeException e) {
                    onFailure.accept(e);
                }
            }
        }.execute();
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
