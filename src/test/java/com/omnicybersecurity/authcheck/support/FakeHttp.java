package com.omnicybersecurity.authcheck.support;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Proxy-backed HTTP message fakes. Montoya's real factories need Burp's runtime,
 * so these model just enough behaviour -- case-insensitive headers and the
 * immutable {@code with*} style -- to test the mutator and analyser honestly.
 */
public final class FakeHttp {

    private FakeHttp() {
    }

    // -- responses -----------------------------------------------------------

    public static HttpResponse response(int status, String body) {
        return response(status, body, Map.of());
    }

    public static HttpResponse response(int status, String body, Map<String, String> headers) {
        Map<String, String> headerMap = new LinkedHashMap<>(headers);
        return (HttpResponse) Proxy.newProxyInstance(
                FakeHttp.class.getClassLoader(),
                new Class<?>[] { HttpResponse.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "statusCode" -> (short) status;
                    case "reasonPhrase" -> "";
                    case "bodyToString" -> body;
                    case "headerValue" -> findIgnoreCase(headerMap, (String) args[0]);
                    case "headers" -> headerList(headerMap);
                    case "toString" -> "FakeResponse(" + status + ")";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(
                            "FakeHttp response does not implement " + method.getName() + "()");
                });
    }

    // -- requests ------------------------------------------------------------

    /** Mutable state behind a fake request, readable from tests. */
    public static final class RequestState {
        final Map<String, String> headers = new LinkedHashMap<>();
        final List<String> appliedParams = new ArrayList<>();
        /** Header names present more than once, as HTTP/2 allows. */
        final Map<String, List<String>> repeated = new LinkedHashMap<>();
        String method = "GET";
        String url = "https://target.example.com/api/orders/1";
        String path = "/api/orders/1";
        String body = "";

        RequestState copy() {
            RequestState clone = new RequestState();
            clone.headers.putAll(headers);
            clone.appliedParams.addAll(appliedParams);
            clone.method = method;
            repeated.forEach((k, v) -> clone.repeated.put(k, new ArrayList<>(v)));
            clone.url = url;
            clone.path = path;
            clone.body = body;
            return clone;
        }

        public String header(String name) {
            for (Map.Entry<String, List<String>> entry : repeated.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                    return entry.getValue().get(0);
                }
            }
            return findIgnoreCase(headers, name);
        }

        /** How many field lines carry this header name. */
        public int count(String name) {
            for (Map.Entry<String, List<String>> entry : repeated.entrySet()) {
                // Once every repeated line is gone, fall through: a header added
                // afterwards lives in the ordinary map.
                if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                    return entry.getValue().size();
                }
            }
            return findIgnoreCase(headers, name) == null ? 0 : 1;
        }

        public boolean has(String name) {
            return header(name) != null;
        }
    }

    /** A fake request also exposes its state so assertions can read it back. */
    interface Stateful {
        RequestState state();
    }

    public static HttpRequest request(Map<String, String> headers) {
        return request(headers, "GET");
    }

    /** Mirrors {@code HttpRequest.httpRequestFromUrl}: a GET carrying the URL. */
    public static HttpRequest requestForUrl(String url) {
        RequestState state = new RequestState();
        state.url = url;
        try {
            java.net.URI uri = java.net.URI.create(url);
            state.headers.put("Host", uri.getHost() == null ? "unknown" : uri.getHost());
            state.path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        } catch (RuntimeException e) {
            state.path = "/";
        }
        return build(state);
    }

    public static HttpRequest request(Map<String, String> headers, String method) {
        RequestState state = new RequestState();
        state.headers.putAll(headers);
        state.method = method;
        return build(state);
    }

    /**
     * A request carrying the same header name several times, as HTTP/2 permits
     * for Cookie. Removal must clear every one of them.
     */
    public static HttpRequest requestWithRepeatedHeader(Map<String, String> headers,
            String repeatedName, List<String> repeatedValues) {
        RequestState state = new RequestState();
        state.headers.putAll(headers);
        state.repeated.put(repeatedName, new ArrayList<>(repeatedValues));
        return build(state);
    }

    private static HttpRequest build(RequestState state) {
        return (HttpRequest) Proxy.newProxyInstance(
                FakeHttp.class.getClassLoader(),
                new Class<?>[] { HttpRequest.class, Stateful.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "state" -> state;
                    case "method" -> state.method;
                    case "url" -> state.url;
                    case "path", "pathWithoutQuery" -> state.path;
                    case "bodyToString" -> state.body;
                    case "withMethod" -> {
                        RequestState next = state.copy();
                        next.method = (String) args[0];
                        yield build(next);
                    }
                    case "withBody" -> {
                        RequestState next = state.copy();
                        next.body = String.valueOf(args[0]);
                        yield build(next);
                    }
                    case "hasHeader" -> state.count((String) args[0]) > 0;
                    case "headerValue" -> state.header((String) args[0]);
                    case "headers" -> headerList(state);
                    case "hasParameter" -> false;
                    case "withRemovedHeader" -> {
                        RequestState next = state.copy();
                        String target = (String) args[0];
                        // Model the pessimistic case: one call clears one field line.
                        boolean removedRepeated = false;
                        for (Map.Entry<String, List<String>> entry : next.repeated.entrySet()) {
                            if (entry.getKey().equalsIgnoreCase(target) && !entry.getValue().isEmpty()) {
                                entry.getValue().remove(0);
                                removedRepeated = true;
                                break;
                            }
                        }
                        if (!removedRepeated) {
                            removeIgnoreCase(next.headers, target);
                        }
                        yield build(next);
                    }
                    case "withUpdatedHeader" -> {
                        RequestState next = state.copy();
                        // Montoya documents this as updating the value of a header;
                        // it does not promise to add a missing one. Model the
                        // strict reading so callers cannot depend on the loose one.
                        if (next.has((String) args[0])) {
                            putIgnoreCase(next.headers, (String) args[0], (String) args[1]);
                        }
                        yield build(next);
                    }
                    case "withAddedHeader" -> {
                        RequestState next = state.copy();
                        putIgnoreCase(next.headers, (String) args[0], (String) args[1]);
                        yield build(next);
                    }
                    case "withUpdatedParameters", "withAddedParameters" -> {
                        RequestState next = state.copy();
                        for (HttpParameter parameter : (HttpParameter[]) args[0]) {
                            next.appliedParams.add(method.getName() + ":" + parameter.type()
                                    + ":" + parameter.name() + "=" + parameter.value());
                        }
                        yield build(next);
                    }
                    case "toString" -> "FakeRequest" + state.headers;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(
                            "FakeHttp request does not implement " + method.getName() + "()");
                });
    }

    public static RequestState stateOf(HttpRequest request) {
        return ((Stateful) request).state();
    }

    // -- exchanges -----------------------------------------------------------

    /** Pairs a request and response, as the engine stores them in a record. */
    public static HttpRequestResponse exchange(HttpRequest request, HttpResponse response) {
        return (HttpRequestResponse) Proxy.newProxyInstance(
                FakeHttp.class.getClassLoader(),
                new Class<?>[] { HttpRequestResponse.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "request" -> request;
                    case "response" -> response;
                    case "hasResponse" -> response != null;
                    case "copyToTempFile" -> proxy;
                    case "statusCode" -> response == null ? (short) 0 : response.statusCode();
                    case "toString" -> "FakeExchange";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(
                            "FakeHttp exchange does not implement " + method.getName() + "()");
                });
    }

    // -- header map helpers (HTTP header names are case-insensitive) ---------

    private static String findIgnoreCase(Map<String, String> map, String name) {
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static void putIgnoreCase(Map<String, String> map, String name, String value) {
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                entry.setValue(value);
                return;
            }
        }
        map.put(name, value);
    }

    private static void removeIgnoreCase(Map<String, String> map, String name) {
        map.keySet().removeIf(key -> key.equalsIgnoreCase(name));
    }

    private static List<HttpHeader> headerList(RequestState state) {
        List<HttpHeader> all = new ArrayList<>(headerList(state.headers));
        state.repeated.forEach((name, values) ->
                values.forEach(value -> all.addAll(headerList(Map.of(name, value)))));
        return all;
    }

    private static List<HttpHeader> headerList(Map<String, String> map) {
        List<HttpHeader> headers = new ArrayList<>();
        map.forEach((name, value) -> headers.add((HttpHeader) Proxy.newProxyInstance(
                FakeHttp.class.getClassLoader(),
                new Class<?>[] { HttpHeader.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "name" -> name;
                    case "value" -> value;
                    case "toString" -> name + ": " + value;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                })));
        return headers;
    }
}
