package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnicybersecurity.authcheck.config.Settings;
import groovy.json.JsonOutput;
import groovy.json.JsonSlurper;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The {@code http} binding handed to auth scripts: a small, deliberately boring
 * HTTP helper on top of {@code api.http()}, so a login flow is a few lines
 * rather than a pile of Montoya boilerplate.
 *
 * <p>Requests sent from here go out through Burp, so they appear in the Logger
 * and honour Burp's upstream proxy configuration. Redirects are <em>not</em>
 * followed by default -- login flows usually need the {@code Set-Cookie} on the
 * 302 itself.
 */
public final class ScriptHttp {

    private final MontoyaApi api;
    private final Settings settings;
    /** Every exchange this helper sent, or null when not recording. */
    private final List<HttpRequestResponse> transcript;

    public ScriptHttp(MontoyaApi api, Settings settings) {
        this(api, settings, false);
    }

    /**
     * @param recording when true, every request sent through this helper is kept
     *                  so the login flow can be reviewed and stored in the project
     */
    public ScriptHttp(MontoyaApi api, Settings settings, boolean recording) {
        this.api = api;
        this.settings = settings;
        this.transcript = recording ? Collections.synchronizedList(new ArrayList<>()) : null;
    }

    /** The login exchanges recorded so far, oldest first. */
    public List<HttpRequestResponse> transcript() {
        if (transcript == null) {
            return List.of();
        }
        synchronized (transcript) {
            return List.copyOf(transcript);
        }
    }

    // -- sending -------------------------------------------------------------

    /**
     * Sends without following redirects.
     *
     * <p>This deliberately ignores the "follow redirects when replaying" setting.
     * That setting is about replaying the request under test; wiring it to script
     * requests too meant turning it on silently changed how logins behaved, and a
     * login's {@code Set-Cookie} usually arrives on the 302 itself -- following it
     * would discard the session the script exists to obtain. Pass an explicit
     * {@code true} when a flow really does need the redirect followed.
     */
    public HttpRequestResponse send(HttpRequest request) {
        return send(request, false);
    }

    public HttpRequestResponse send(HttpRequest request, boolean followRedirects) {
        RequestOptions options = RequestOptions.requestOptions()
                .withRedirectionMode(followRedirects ? RedirectionMode.ALWAYS : RedirectionMode.NEVER)
                .withResponseTimeout(settings.responseTimeoutMillis());
        HttpRequestResponse exchange = api.http().sendRequest(request, options);
        if (transcript != null && exchange != null) {
            // Keep it on disk rather than heap: login responses can be whole pages.
            transcript.add(exchange.copyToTempFile());
        }
        return exchange;
    }

    /** Builds a bare GET request for a URL, ready to be customised. */
    public HttpRequest request(String url) {
        return HttpRequest.httpRequestFromUrl(url);
    }

    public HttpRequestResponse get(String url) {
        return send(HttpRequest.httpRequestFromUrl(url));
    }

    public HttpRequestResponse get(String url, Map<String, String> headers) {
        return send(withHeaders(HttpRequest.httpRequestFromUrl(url), headers));
    }

    public HttpRequestResponse post(String url, String body, String contentType) {
        return post(url, body, contentType, Map.of());
    }

    public HttpRequestResponse post(String url, String body, String contentType, Map<String, String> headers) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withBody(body == null ? "" : body)
                .withUpdatedHeader("Content-Type", contentType);
        return send(withHeaders(request, headers));
    }

    /** POSTs JSON. Accepts a String, or any Map/List which is serialised for you. */
    public HttpRequestResponse postJson(String url, Object body) {
        return postJson(url, body, Map.of());
    }

    public HttpRequestResponse postJson(String url, Object body, Map<String, String> headers) {
        String json = (body instanceof String text) ? text : JsonOutput.toJson(body);
        return post(url, json, "application/json", headers);
    }

    /** POSTs a URL-encoded form body, encoding the values for you. */
    public HttpRequestResponse postForm(String url, Map<String, String> form) {
        return postForm(url, form, Map.of());
    }

    public HttpRequestResponse postForm(String url, Map<String, String> form, Map<String, String> headers) {
        return post(url, encodeForm(form), "application/x-www-form-urlencoded", headers);
    }

    private static HttpRequest withHeaders(HttpRequest request, Map<String, String> headers) {
        HttpRequest result = request;
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                result = result.withUpdatedHeader(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }
        return result;
    }

    public String encodeForm(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        if (form != null) {
            for (Map.Entry<String, String> entry : form.entrySet()) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(urlEncode(entry.getKey())).append('=')
                        .append(urlEncode(String.valueOf(entry.getValue())));
            }
        }
        return sb.toString();
    }

    public String urlEncode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    // -- reading responses ---------------------------------------------------

    /** Parses a JSON response body into Groovy maps/lists. */
    public Object json(HttpRequestResponse exchange) {
        if (exchange == null || !exchange.hasResponse()) {
            throw new IllegalStateException("No response to parse as JSON");
        }
        return json(exchange.response().bodyToString());
    }

    public Object json(HttpResponse response) {
        if (response == null) {
            throw new IllegalStateException("No response to parse as JSON");
        }
        return json(response.bodyToString());
    }

    public Object json(String text) {
        return new JsonSlurper().parseText(text == null ? "" : text);
    }

    /** Value of a {@code Set-Cookie} cookie on the response, or null. */
    public String cookie(HttpRequestResponse exchange, String name) {
        if (exchange == null || !exchange.hasResponse()) {
            return null;
        }
        return exchange.response().cookieValue(name);
    }

    /** All cookies set by the response, as a name to value map. */
    public Map<String, String> cookies(HttpRequestResponse exchange) {
        Map<String, String> out = new LinkedHashMap<>();
        if (exchange != null && exchange.hasResponse()) {
            for (Cookie cookie : exchange.response().cookies()) {
                out.put(cookie.name(), cookie.value());
            }
        }
        return out;
    }

    public short status(HttpRequestResponse exchange) {
        return exchange != null && exchange.hasResponse() ? exchange.response().statusCode() : (short) 0;
    }

    public String body(HttpRequestResponse exchange) {
        return exchange != null && exchange.hasResponse() ? exchange.response().bodyToString() : "";
    }

    public String header(HttpRequestResponse exchange, String name) {
        return exchange != null && exchange.hasResponse() ? exchange.response().headerValue(name) : null;
    }

    /** First capture group of a regex against text, or null if it does not match. */
    public String extract(String text, String regex) {
        return extract(text, regex, 1);
    }

    public String extract(String text, String regex, int group) {
        if (text == null) {
            return null;
        }
        Matcher matcher = Pattern.compile(regex).matcher(text);
        if (!matcher.find()) {
            return null;
        }
        return matcher.groupCount() >= group ? matcher.group(group) : matcher.group();
    }

    /** Convenience for pulling a value out of a response body by regex. */
    public String extractFrom(HttpRequestResponse exchange, String regex) {
        return extract(body(exchange), regex, 1);
    }
}
