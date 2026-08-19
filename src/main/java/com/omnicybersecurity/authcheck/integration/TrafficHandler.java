package com.omnicybersecurity.authcheck.integration;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;
import com.omnicybersecurity.authcheck.engine.AuthCheckEngine;

/**
 * Watches Burp's traffic and hands completed exchanges to the engine.
 *
 * <p>Testing happens on the response hook because the baseline response is what
 * "authorised access" gets compared against. Nothing is modified and no work is
 * done on Burp's own thread -- the engine queues and returns immediately.
 */
public final class TrafficHandler implements HttpHandler {

    private final AuthCheckEngine engine;
    private final Logging logging;

    public TrafficHandler(AuthCheckEngine engine, Logging logging) {
        this.engine = engine;
        this.logging = logging;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            engine.offerForAutoTest(response.initiatingRequest(), response, response.toolSource().toolType());
        } catch (Exception e) {
            // A bug in intake must never disturb the traffic the tester is proxying.
            logging.logToError("[auth-check] Failed to queue " + response.initiatingRequest().url(), e);
        }
        return ResponseReceivedAction.continueWith(response);
    }
}
