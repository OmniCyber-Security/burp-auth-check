package com.omnicybersecurity.authcheck.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.Verdict;
import com.omnicybersecurity.authcheck.util.Patterns;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decides what a replayed response means.
 *
 * <p>The central judgement is "did this identity get the same thing the baseline
 * user got?". Body text is compared with a Sorensen-Dice coefficient over
 * character shingles, which tolerates per-session noise (CSRF tokens, timestamps)
 * while still registering genuinely different content -- important because a
 * user legitimately receiving <em>their own</em> data must not read as a bypass.
 *
 * <p>A bypass is only ever claimed when the baseline itself was a success.
 * Comparing against a 404 or a 500 proves nothing, so those degrade to
 * "needs review" with the reason stated.
 */
public final class ResponseAnalyser {

    /** Attributes that indicate a substantive difference, not session noise. */
    private static final Set<AttributeType> MEANINGFUL_VARIATIONS = Set.of(
            AttributeType.STATUS_CODE,
            AttributeType.PAGE_TITLE,
            AttributeType.VISIBLE_TEXT,
            AttributeType.BODY_CONTENT,
            AttributeType.TAG_NAMES,
            AttributeType.DIV_IDS,
            AttributeType.LINE_COUNT,
            AttributeType.WORD_COUNT,
            AttributeType.VISIBLE_WORD_COUNT,
            AttributeType.LOCATION);

    private static final int SHINGLE_SIZE = 8;
    private static final int SHINGLE_STEP = 2;

    /** Minimum length for a run to be considered a session token. */
    private static final int MIN_TOKEN_LENGTH = 16;
    /**
     * Token alphabet plus optional base64 padding. {@code =}, {@code _} and
     * {@code -} are delimiters rather than token characters: including them lets a
     * run swallow its own field name, so {@code csrf=<32 hex>} would be masked
     * whole and the surrounding structure lost. Base64url tokens split at those
     * characters and each long piece is masked on its own.
     */
    private static final Pattern TOKEN_RUN =
            Pattern.compile("[A-Za-z0-9+/]{" + MIN_TOKEN_LENGTH + ",}={0,2}");
    /**
     * Sentinel-wrapped placeholder. The control characters cannot occur in a
     * token run, so a body that literally contains "tok" is never confused with a
     * masked token.
     */
    static final String TOKEN_PLACEHOLDER = "\u0001tok\u0001";

    private final MontoyaApi api;
    private final Configuration configuration;

    public ResponseAnalyser(MontoyaApi api, Configuration configuration) {
        this.api = api;
        this.configuration = configuration;
    }

    /**
     * Analysis of one variant response against the baseline.
     *
     * @param verdict    the conclusion
     * @param similarity 0..1 body similarity
     * @param detail     why this verdict was reached
     */
    public record Analysis(Verdict verdict, double similarity, String detail) {
    }

    public Analysis analyse(HttpResponse baseline, HttpResponse variant) {
        if (variant == null) {
            return new Analysis(Verdict.ERROR, 0d, "No response received for the replayed request.");
        }
        Settings settings = configuration.settings();

        String denialReason = denialReason(variant, settings);
        if (denialReason != null) {
            return new Analysis(Verdict.ENFORCED, similarity(baseline, variant, settings),
                    "Access denied: " + denialReason);
        }

        if (baseline == null) {
            return new Analysis(Verdict.NEEDS_REVIEW, 0d,
                    "No baseline response to compare against; judge the response manually.");
        }

        double similarity = similarity(baseline, variant, settings);
        boolean statusMatches = baseline.statusCode() == variant.statusCode();
        boolean baselineSucceeded = isSuccess(baseline.statusCode());

        boolean same = settings.useBurpVariationsAnalyzer()
                ? statusMatches && !variesMeaningfully(baseline, variant)
                : statusMatches && similarity * 100 >= settings.sameThresholdPercent();

        if (!baselineSucceeded) {
            return new Analysis(Verdict.NEEDS_REVIEW, similarity,
                    "Baseline returned HTTP " + baseline.statusCode()
                    + ", so it does not establish what authorised access looks like."
                    + (same ? " The replay matched it." : " The replay differed from it."));
        }

        if (same) {
            return new Analysis(Verdict.BYPASSED, similarity,
                    "Same HTTP " + variant.statusCode() + " response as the baseline user ("
                    + Math.round(similarity * 100) + "% body similarity) -- this identity reached the resource.");
        }

        if (!statusMatches) {
            return new Analysis(Verdict.NEEDS_REVIEW, similarity,
                    "HTTP " + variant.statusCode() + " vs baseline HTTP " + baseline.statusCode()
                    + " and not a recognised denial (" + Math.round(similarity * 100)
                    + "% body similarity). Check whether the response leaks anything.");
        }

        return new Analysis(Verdict.NEEDS_REVIEW, similarity,
                "Same HTTP " + variant.statusCode() + " but different content ("
                + Math.round(similarity * 100) + "% body similarity). Often the identity's own data -- confirm "
                + "the response does not contain the baseline user's data.");
    }

    /** Null when the response is not a recognised denial, otherwise the reason. */
    public String denialReason(HttpResponse response, Settings settings) {
        if (response == null) {
            return null;
        }
        short status = response.statusCode();
        List<Integer> deniedCodes = Text.splitInts(settings.deniedStatusCodes());
        if (deniedCodes.contains((int) status)) {
            return "HTTP " + status;
        }
        if (settings.treatLoginRedirectAsEnforced() && status >= 300 && status < 400) {
            String location = response.headerValue("Location");
            if (location != null && Patterns.find(settings.loginRedirectRegex(), location)) {
                return "redirected to login (" + Text.abbreviate(location, 80) + ")";
            }
        }
        String bodyRegex = settings.deniedBodyRegex();
        if (!Text.isBlank(bodyRegex)) {
            String body = truncate(response.bodyToString(), settings.maxCompareBytes());
            if (Patterns.find(bodyRegex, body)) {
                return "response matched the denial pattern";
            }
        }
        return null;
    }

    public static boolean isSuccess(short status) {
        return status >= 200 && status < 300;
    }

    // -- similarity ----------------------------------------------------------

    private double similarity(HttpResponse baseline, HttpResponse variant, Settings settings) {
        if (baseline == null || variant == null) {
            return 0d;
        }
        String left = truncate(baseline.bodyToString(), settings.maxCompareBytes());
        String right = truncate(variant.bodyToString(), settings.maxCompareBytes());
        return dice(left, right);
    }

    /**
     * Sorensen-Dice coefficient over hashed character shingles.
     *
     * <p>Normalisation is deliberately narrow: whitespace is collapsed and
     * high-entropy token-like runs (16+ characters mixing letters and digits --
     * CSRF tokens, session ids, nonces) are masked. Everything a human would
     * recognise as data is left alone, because names, amounts and short ids are
     * exactly what distinguishes "the other user's record" from "the same record",
     * and masking those would manufacture false bypasses.
     */
    static double dice(String left, String right) {
        int[] a = shingles(left);
        int[] b = shingles(right);
        if (a.length == 0 && b.length == 0) {
            return 1d;
        }
        if (a.length == 0 || b.length == 0) {
            return 0d;
        }
        int intersection = 0;
        int i = 0;
        int j = 0;
        while (i < a.length && j < b.length) {
            if (a[i] == b[j]) {
                intersection++;
                i++;
                j++;
            } else if (a[i] < b[j]) {
                i++;
            } else {
                j++;
            }
        }
        return (2d * intersection) / (a.length + b.length);
    }

    /** Sorted, de-duplicated shingle hashes for a body. */
    private static int[] shingles(String text) {
        String normalised = maskHighEntropyTokens(collapseWhitespace(text));
        int length = normalised.length();
        if (length == 0) {
            return new int[0];
        }
        if (length <= SHINGLE_SIZE) {
            return new int[] { normalised.hashCode() };
        }
        int count = ((length - SHINGLE_SIZE) / SHINGLE_STEP) + 1;
        int[] hashes = new int[count];
        int index = 0;
        for (int start = 0; start + SHINGLE_SIZE <= length && index < count; start += SHINGLE_STEP) {
            int hash = 0;
            for (int offset = 0; offset < SHINGLE_SIZE; offset++) {
                hash = hash * 31 + normalised.charAt(start + offset);
            }
            hashes[index++] = hash;
        }
        Arrays.sort(hashes);
        // De-duplicate in place so the coefficient is over sets, not multisets.
        int unique = 0;
        for (int position = 0; position < hashes.length; position++) {
            if (position == 0 || hashes[position] != hashes[position - 1]) {
                hashes[unique++] = hashes[position];
            }
        }
        return unique == hashes.length ? hashes : Arrays.copyOf(hashes, unique);
    }

    /**
     * Replaces token-like runs with a placeholder so a per-session CSRF token or
     * session id does not make two copies of the same page look different.
     *
     * <p>A run only qualifies when it is at least 16 characters of token alphabet
     * <em>and</em> mixes letters with digits. That catches hex, base64 and JWT
     * segments while leaving names, prices, dates and short numeric ids intact.
     */
    static String maskHighEntropyTokens(String text) {
        if (text == null || text.length() < MIN_TOKEN_LENGTH) {
            return text == null ? "" : text;
        }
        Matcher matcher = TOKEN_RUN.matcher(text);
        StringBuilder out = new StringBuilder(text.length());
        int last = 0;
        while (matcher.find()) {
            String run = matcher.group();
            if (!looksLikeToken(run)) {
                continue;
            }
            out.append(text, last, matcher.start()).append(TOKEN_PLACEHOLDER);
            last = matcher.end();
        }
        if (last == 0) {
            return text;
        }
        return out.append(text, last, text.length()).toString();
    }

    private static boolean looksLikeToken(String run) {
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (int i = 0; i < run.length(); i++) {
            char c = run.charAt(i);
            if (Character.isLetter(c)) {
                hasLetter = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            }
            if (hasLetter && hasDigit) {
                return true;
            }
        }
        return false;
    }

    private static String collapseWhitespace(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(text.length());
        boolean lastWasSpace = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c)) {
                if (!lastWasSpace) {
                    sb.append(' ');
                    lastWasSpace = true;
                }
            } else {
                sb.append(c);
                lastWasSpace = false;
            }
        }
        return sb.toString().trim();
    }

    private static String truncate(String text, int max) {
        if (text == null) {
            return "";
        }
        return text.length() <= max ? text : text.substring(0, max);
    }

    /** Burp's own variations analyser, offered as an alternative comparator. */
    private boolean variesMeaningfully(HttpResponse baseline, HttpResponse variant) {
        ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
        analyzer.updateWith(baseline);
        analyzer.updateWith(variant);
        for (AttributeType attribute : analyzer.variantAttributes()) {
            if (MEANINGFUL_VARIATIONS.contains(attribute)) {
                return true;
            }
        }
        return false;
    }
}
