package com.omnicybersecurity.authcheck.engine;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.model.ParamSpec;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rewrites a captured request so it is sent as a different identity, or as
 * nobody at all.
 *
 * <p>Order matters: the original identity's credentials are stripped first, then
 * the target identity's material is applied, then the identity's static headers
 * go on last so a tester can always force a specific value.
 */
public final class RequestMutator {

    private static final String COOKIE_HEADER = "Cookie";

    private final Configuration configuration;

    public RequestMutator(Configuration configuration) {
        this.configuration = configuration;
    }

    /** Rewrites {@code base} to carry {@code identity}'s session. */
    public HttpRequest applyIdentity(HttpRequest base, Identity identity, AuthMaterial material) {
        List<String> strip = new ArrayList<>(Text.splitList(identity.stripHeaders()));
        strip.addAll(material.removeHeaders());

        boolean cookiesStripped = containsIgnoreCase(strip, COOKIE_HEADER);
        Map<String, String> cookies = new LinkedHashMap<>();
        if (!cookiesStripped) {
            // Keep the original request's non-session cookies (consent banners,
            // locale, A/B buckets) so the app behaves the same for both users.
            cookies.putAll(parseCookieHeader(base.headerValue(COOKIE_HEADER)));
        }
        cookies.putAll(material.cookies());

        HttpRequest request = removeHeaders(base, strip);
        request = applyHeaders(request, material.headers());
        request = applyCookies(request, cookies);
        request = applyParams(request, material.params());
        request = applyHeaders(request, identity.staticHeaderMap());
        return request;
    }

    /** Strips every configured auth header so the request goes out anonymous. */
    public HttpRequest applyUnauthenticated(HttpRequest base) {
        List<String> strip = Text.splitList(configuration.settings().unauthStripHeaders());
        return removeHeaders(base, strip);
    }

    // -- helpers -------------------------------------------------------------

    private static HttpRequest removeHeaders(HttpRequest request, List<String> names) {
        HttpRequest result = request;
        for (String name : names) {
            if (Text.isBlank(name)) {
                continue;
            }
            String trimmed = name.trim();
            // Only remove what is present: Montoya throws on unknown headers.
            if (result.hasHeader(trimmed)) {
                result = result.withRemovedHeader(trimmed);
            }
        }
        return result;
    }

    private static HttpRequest applyHeaders(HttpRequest request, Map<String, String> headers) {
        HttpRequest result = request;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (Text.isBlank(entry.getKey())) {
                continue;
            }
            result = setHeader(result, entry.getKey().trim(), Text.nullToEmpty(entry.getValue()));
        }
        return result;
    }

    /**
     * Sets a header whether or not it is already present.
     *
     * <p>Montoya documents {@code withUpdatedHeader} as updating the value of a
     * header and does not promise it adds a missing one. That distinction matters
     * here: credentials are stripped before the identity's are applied, so by the
     * time this runs the header is usually <em>absent</em>. Relying on the loose
     * behaviour would silently send the replay with no credentials at all, which
     * reads as a bypass or an auth failure rather than as a bug.
     */
    private static HttpRequest setHeader(HttpRequest request, String name, String value) {
        return request.hasHeader(name)
                ? request.withUpdatedHeader(name, value)
                : request.withAddedHeader(name, value);
    }

    private static HttpRequest applyCookies(HttpRequest request, Map<String, String> cookies) {
        if (cookies.isEmpty()) {
            return request;
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(entry.getKey()).append('=').append(Text.nullToEmpty(entry.getValue()));
        }
        return setHeader(request, COOKIE_HEADER, sb.toString());
    }

    private static HttpRequest applyParams(HttpRequest request, List<ParamSpec> params) {
        HttpRequest result = request;
        for (ParamSpec spec : params) {
            HttpParameter parameter = HttpParameter.parameter(spec.name(), spec.value(), spec.type());
            // withUpdatedParameters only touches parameters that already exist,
            // so a missing one has to be added instead.
            if (result.hasParameter(spec.name(), spec.type())) {
                result = result.withUpdatedParameters(parameter);
            } else {
                result = result.withAddedParameters(parameter);
            }
        }
        return result;
    }

    private static Map<String, String> parseCookieHeader(String header) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (Text.isBlank(header)) {
            return cookies;
        }
        for (String part : header.split(";")) {
            int equals = part.indexOf('=');
            if (equals > 0) {
                cookies.put(part.substring(0, equals).trim(), part.substring(equals + 1).trim());
            }
        }
        return cookies;
    }

    private static boolean containsIgnoreCase(List<String> values, String needle) {
        for (String value : values) {
            if (value != null && value.trim().equalsIgnoreCase(needle)) {
                return true;
            }
        }
        return false;
    }
}
