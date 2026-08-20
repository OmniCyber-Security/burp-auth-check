package com.omnicybersecurity.authcheck.auth;

import com.omnicybersecurity.authcheck.util.Text;

import java.net.URI;
import java.util.List;
import java.util.Locale;

/**
 * One credential variable an auth script declares for itself.
 *
 * <p>Before this existed the contract between a script and its identity was
 * prose in the opening comment: the tester read it, guessed at the names, and
 * found out they had guessed wrong when the script threw. A declaration turns
 * that into a form with the right fields already on it.
 *
 * @param name         the key the script reads as {@code creds.<name>}
 * @param label        what the form calls it; the name when blank
 * @param type         which widget the tester gets, and how the value is checked
 * @param required     whether the run is blocked when the value is blank
 * @param defaultValue used when the tester leaves the field empty; implies optional
 * @param help         one line under the field explaining when to set it
 * @param choices      the permitted values, for {@link Type#CHOICE}
 */
public record ScriptParam(String name, String label, Type type, boolean required,
        String defaultValue, String help, List<String> choices) {

    /**
     * The kinds of value a script can ask for. Deliberately few: each one has to
     * earn its place by changing the widget or the check, and anything more
     * elaborate belongs in the script.
     */
    public enum Type {
        /** Free text. */
        STRING,
        /** Free text, masked in the UI. */
        SECRET,
        /** Whole number. */
        INT,
        /** True or false, shown as a checkbox. */
        BOOL,
        /** Absolute URL, e.g. a base address. */
        URL,
        /** One of a fixed set of values, shown as a drop-down. */
        CHOICE,
        /** Multi-line text, e.g. a PEM key. */
        TEXT;

        /** Parses a declared type, tolerating the obvious synonyms. Null if unknown. */
        public static Type parse(String value) {
            if (Text.isBlank(value)) {
                return null;
            }
            return switch (value.trim().toUpperCase(Locale.ROOT)) {
                case "STRING", "STR" -> STRING;
                case "SECRET", "PASSWORD" -> SECRET;
                case "INT", "INTEGER", "NUMBER", "LONG" -> INT;
                case "BOOL", "BOOLEAN", "FLAG" -> BOOL;
                case "URL", "URI" -> URL;
                case "CHOICE", "ENUM", "OPTION" -> CHOICE;
                case "TEXT", "MULTILINE" -> TEXT;
                default -> null;
            };
        }

        /** The declarable names, for the "unknown type" message. */
        public static String names() {
            StringBuilder sb = new StringBuilder();
            for (Type type : values()) {
                sb.append(sb.isEmpty() ? "" : ", ").append(type.name());
            }
            return sb.toString();
        }
    }

    public ScriptParam {
        name = Text.nullToEmpty(name).trim();
        label = Text.nullToEmpty(label).trim();
        type = type == null ? Type.STRING : type;
        defaultValue = Text.nullToEmpty(defaultValue);
        help = Text.nullToEmpty(help).trim();
        choices = choices == null ? List.of() : List.copyOf(choices);
    }

    public static ScriptParam of(String name, Type type) {
        return new ScriptParam(name, "", type, false, "", "", List.of());
    }

    /** What the form calls this field. */
    public String displayLabel() {
        return label.isEmpty() ? name : label;
    }

    public boolean secret() {
        return type == Type.SECRET;
    }

    public boolean hasDefault() {
        return !defaultValue.isEmpty();
    }

    /**
     * Why this value is unusable, or null when it is fine. Blank is always fine
     * here -- an unset required field is reported separately, because "you have
     * not filled this in yet" and "what you typed is not a number" are different
     * things to tell someone.
     */
    public String problemWith(String value) {
        if (Text.isBlank(value)) {
            return null;
        }
        String trimmed = value.trim();
        return switch (type) {
            case INT -> isInteger(trimmed) ? null : "must be a whole number";
            case BOOL -> isBoolean(trimmed) ? null : "must be true or false";
            case URL -> isAbsoluteUrl(trimmed)
                    ? null : "must be an absolute URL, e.g. https://target.example.com";
            case CHOICE -> choices.isEmpty() || choices.contains(trimmed)
                    ? null : "must be one of: " + String.join(", ", choices);
            case STRING, SECRET, TEXT -> null;
        };
    }

    private static boolean isInteger(String value) {
        try {
            Long.parseLong(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isBoolean(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.equals("true") || lower.equals("false");
    }

    private static boolean isAbsoluteUrl(String value) {
        try {
            // A bare host is the mistake worth catching: scripts concatenate
            // these ("${creds.base}/login"), so a missing scheme fails later and
            // less clearly than it does here.
            URI uri = new URI(value);
            return uri.isAbsolute() && uri.getScheme() != null;
        } catch (Exception e) {
            return false;
        }
    }
}
