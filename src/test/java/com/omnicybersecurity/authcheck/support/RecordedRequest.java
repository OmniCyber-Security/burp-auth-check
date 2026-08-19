package com.omnicybersecurity.authcheck.support;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * Captures what {@code api.http().sendRequest(...)} was actually asked to do, so
 * tests can assert on the options a script request was sent with rather than on
 * the code that builds them.
 */
public final class RecordedRequest {

    // Scripts run on the engine's own executor thread, so this cannot be
    // thread-confined to the test thread. The factory hook that populates it is
    // static, so the collection is too; tests clear it in setup.
    private static final List<RedirectionMode> REDIRECT_MODES =
            java.util.Collections.synchronizedList(new ArrayList<>());

    private final List<HttpRequest> sent = new ArrayList<>();

    public List<HttpRequest> sent() {
        return sent;
    }

    /** Redirection modes requested since the last {@link #reset()}. */
    public List<RedirectionMode> redirectionModes() {
        synchronized (REDIRECT_MODES) {
            return List.copyOf(REDIRECT_MODES);
        }
    }

    public void reset() {
        sent.clear();
        REDIRECT_MODES.clear();
    }

    /** A RequestOptions that remembers the redirection mode it was given. */
    static RequestOptions newOptions() {
        return (RequestOptions) Proxy.newProxyInstance(
                RecordedRequest.class.getClassLoader(),
                new Class<?>[] { RequestOptions.class },
                (proxy, method, args) -> {
                    if ("withRedirectionMode".equals(method.getName())) {
                        REDIRECT_MODES.add((RedirectionMode) args[0]);
                    }
                    // Every with* call is a builder step returning itself.
                    return proxy;
                });
    }

    /** A MontoyaApi whose http() records requests and returns a canned response. */
    public MontoyaApi api(HttpRequestResponse response) {
        Logging logging = (Logging) Proxy.newProxyInstance(
                RecordedRequest.class.getClassLoader(), new Class<?>[] { Logging.class },
                (proxy, method, args) -> method.getReturnType() == PrintStream.class
                        ? new PrintStream(OutputStream.nullOutputStream()) : null);

        Http http = (Http) Proxy.newProxyInstance(
                RecordedRequest.class.getClassLoader(), new Class<?>[] { Http.class },
                (proxy, method, args) -> {
                    if ("sendRequest".equals(method.getName())) {
                        sent.add((HttpRequest) args[0]);
                        return response;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });

        return (MontoyaApi) Proxy.newProxyInstance(
                RecordedRequest.class.getClassLoader(), new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "http" -> http;
                    case "logging" -> logging;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
