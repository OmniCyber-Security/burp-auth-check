package com.omnicybersecurity.authcheck.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.util.Patterns;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.Locale;
import java.util.function.Predicate;

/**
 * Decides whether a captured request is worth testing at all.
 *
 * <p>Every request that gets through is replayed once per identity, so filtering
 * is what keeps a busy proxy from turning into a queue of pointless work. Kept
 * separate from the engine so the rules can be tested on their own.
 *
 * <p>These rules apply to automatic testing only. "Send to Auth Check" is an
 * explicit instruction and bypasses all of them.
 */
public final class TrafficFilter {

    private final Settings settings;
    private final Predicate<String> inScope;

    public TrafficFilter(Settings settings, Predicate<String> inScope) {
        this.settings = settings;
        this.inScope = inScope;
    }

    /** Null when the request should be tested, otherwise why it was skipped. */
    public String rejectionReason(HttpRequest request, HttpResponse response) {
        String url = request.url();

        if (settings.onlyInScope() && !inScope.test(url)) {
            return "out of scope";
        }

        // Preflights and probes carry no authorisation decision worth testing,
        // and one OPTIONS per request would otherwise triple the noise.
        String method = request.method();
        for (String skip : Text.splitList(settings.skipMethods())) {
            if (skip.equalsIgnoreCase(method)) {
                return "method " + method + " is filtered out";
            }
        }

        if (settings.skipStaticResources()) {
            String extension = request.fileExtension();
            if (!Text.isBlank(extension)) {
                String needle = extension.toLowerCase(Locale.ROOT);
                for (String skip : Text.splitList(settings.skipExtensions())) {
                    if (needle.equalsIgnoreCase(skip)) {
                        return "static resource (." + extension + ")";
                    }
                }
            }
        }

        if (response != null && Text.splitInts(settings.skipStatusCodes()).contains((int) response.statusCode())) {
            return "baseline status " + response.statusCode() + " is filtered out";
        }

        String include = settings.includeUrlRegex();
        if (!Text.isBlank(include) && !Patterns.find(include, url)) {
            return "URL does not match the include pattern";
        }

        String exclude = settings.excludeUrlRegex();
        if (!Text.isBlank(exclude) && Patterns.find(exclude, url)) {
            return "URL matches the exclude pattern";
        }

        return null;
    }

    public boolean shouldTest(HttpRequest request, HttpResponse response) {
        return rejectionReason(request, response) == null;
    }
}
