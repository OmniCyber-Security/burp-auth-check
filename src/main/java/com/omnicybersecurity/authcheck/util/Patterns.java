package com.omnicybersecurity.authcheck.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Caches compiled regexes so hot paths can be driven straight from the
 * user-editable settings strings without recompiling per request. Invalid or
 * blank expressions resolve to {@code null}, which callers treat as "no rule".
 */
public final class Patterns {

    private static final Map<String, Object> CACHE = new ConcurrentHashMap<>();
    private static final Map<String, Object> CACHE_IGNORING_CASE = new ConcurrentHashMap<>();
    private static final Object INVALID = new Object();

    private Patterns() {
    }

    public static Pattern compile(String regex) {
        return compile(regex, CACHE, 0);
    }

    private static Pattern compile(String regex, Map<String, Object> cache, int flags) {
        if (Text.isBlank(regex)) {
            return null;
        }
        Object cached = cache.computeIfAbsent(regex, key -> {
            try {
                return Pattern.compile(key, flags);
            } catch (PatternSyntaxException e) {
                return INVALID;
            }
        });
        return cached == INVALID ? null : (Pattern) cached;
    }

    /** Validates an expression for the settings UI. Returns null when fine. */
    public static String validationError(String regex) {
        if (Text.isBlank(regex)) {
            return null;
        }
        try {
            Pattern.compile(regex);
            return null;
        } catch (PatternSyntaxException e) {
            return e.getDescription();
        }
    }

    public static boolean find(String regex, String haystack) {
        if (haystack == null) {
            return false;
        }
        Pattern pattern = compile(regex);
        return pattern != null && pattern.matcher(haystack).find();
    }

    /** Like {@link #find} but ignoring case (Unicode-aware). */
    public static boolean findIgnoringCase(String regex, String haystack) {
        if (haystack == null) {
            return false;
        }
        Pattern pattern = compile(regex, CACHE_IGNORING_CASE, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        return pattern != null && pattern.matcher(haystack).find();
    }
}
