package com.omnicybersecurity.authcheck.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnicybersecurity.authcheck.auth.SessionManager;
import com.omnicybersecurity.authcheck.config.Configuration;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.model.VariantResult;
import com.omnicybersecurity.authcheck.model.Verdict;
import com.omnicybersecurity.authcheck.util.Patterns;
import com.omnicybersecurity.authcheck.util.Text;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Orchestrates the actual authorisation testing: decide whether a request is
 * worth testing, replay it once per identity plus once with no credentials at
 * all, judge each response, and publish a record.
 */
public final class AuthCheckEngine {

    private final MontoyaApi api;
    private final Configuration configuration;
    private final SessionManager sessionManager;
    private final ResponseAnalyser analyser;
    private final RequestMutator mutator;
    private final TrafficFilter filter;
    private final RecordStore records;

    private final ThreadPoolExecutor autoExecutor;
    private final ExecutorService manualExecutor;

    private final Set<String> seenRequests = ConcurrentHashMap.newKeySet();
    private final AtomicInteger recordCounter = new AtomicInteger();
    private final AtomicInteger droppedCount = new AtomicInteger();
    private final AtomicInteger skippedCount = new AtomicInteger();

    private volatile Runnable statusListener = () -> { };

    public AuthCheckEngine(MontoyaApi api, Configuration configuration, SessionManager sessionManager,
            RecordStore records) {
        this.api = api;
        this.configuration = configuration;
        this.sessionManager = sessionManager;
        this.records = records;
        this.analyser = new ResponseAnalyser(api, configuration);
        this.mutator = new RequestMutator(configuration);
        this.filter = new TrafficFilter(configuration.settings(), url -> api.scope().isInScope(url));

        Settings settings = configuration.settings();
        AtomicInteger threadCounter = new AtomicInteger();
        this.autoExecutor = new ThreadPoolExecutor(
                settings.threadCount(), settings.threadCount(), 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(settings.queueCapacity()),
                task -> {
                    Thread thread = new Thread(task, "auth-check-worker-" + threadCounter.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                },
                (task, executor) -> {
                    // Shedding load is better than unbounded memory growth or
                    // blocking Burp's proxy threads.
                    droppedCount.incrementAndGet();
                    statusListener.run();
                });
        this.manualExecutor = Executors.newFixedThreadPool(Math.max(2, settings.threadCount()), task -> {
            Thread thread = new Thread(task, "auth-check-manual-" + threadCounter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });

        configuration.onSettingsChanged(this::applySettings);
    }

    private void applySettings() {
        int threads = configuration.settings().threadCount();
        // Grow before shrinking so the pool never transiently has max < core.
        if (threads > autoExecutor.getCorePoolSize()) {
            autoExecutor.setMaximumPoolSize(threads);
            autoExecutor.setCorePoolSize(threads);
        } else if (threads < autoExecutor.getCorePoolSize()) {
            autoExecutor.setCorePoolSize(threads);
            autoExecutor.setMaximumPoolSize(threads);
        }
    }

    public void onStatusChanged(Runnable listener) {
        this.statusListener = listener;
    }

    // -- intake --------------------------------------------------------------

    /**
     * Offers proxied traffic for automatic testing. Returns quietly when the
     * request is filtered out, already seen, or auto-testing is off.
     */
    public void offerForAutoTest(HttpRequest request, HttpResponse response, ToolType toolType) {
        Settings settings = configuration.settings();
        if (!settings.autoTestEnabled()) {
            return;
        }
        if (toolType == ToolType.EXTENSIONS || !settings.sourceTools().contains(toolType)) {
            return;
        }
        if (!hasSomethingToTest()) {
            return;
        }
        if (!filter.shouldTest(request, response)) {
            skippedCount.incrementAndGet();
            return;
        }
        if (settings.dedupeRequests() && !seenRequests.add(dedupeKey(request, settings))) {
            skippedCount.incrementAndGet();
            return;
        }
        // Move the payload off Burp's proxy thread and out of heap before queueing.
        HttpRequestResponse baseline = HttpRequestResponse
                .httpRequestResponse(request, response)
                .copyToTempFile();
        String source = toolType.toolName();
        autoExecutor.execute(() -> runAndPublish(baseline, source));
    }

    /** Tests a request on demand, ignoring every filter and the dedupe cache. */
    public void submitManual(List<HttpRequestResponse> exchanges) {
        for (HttpRequestResponse exchange : exchanges) {
            if (exchange == null) {
                continue;
            }
            HttpRequestResponse baseline = exchange.copyToTempFile();
            manualExecutor.execute(() -> runAndPublish(baseline, "Manual"));
        }
    }

    /** Re-runs an existing record's baseline request. */
    public void retest(List<AuthTestRecord> selected) {
        List<HttpRequestResponse> exchanges = new ArrayList<>();
        for (AuthTestRecord record : selected) {
            exchanges.add(record.baseline());
        }
        submitManual(exchanges);
    }

    private boolean hasSomethingToTest() {
        return !configuration.enabledIdentities().isEmpty() || configuration.settings().testUnauthenticated();
    }

    // -- filtering -----------------------------------------------------------

    private String dedupeKey(HttpRequest request, Settings settings) {
        StringBuilder key = new StringBuilder()
                .append(request.method()).append(' ')
                .append(request.httpService().host()).append(':')
                .append(request.httpService().port())
                .append(request.pathWithoutQuery());
        if (settings.dedupeIncludesParamNames()) {
            // Same endpoint with a different parameter *shape* is a different
            // test; the same endpoint with different ids is not.
            List<String> names = new ArrayList<>();
            for (ParsedHttpParameter parameter : request.parameters()) {
                names.add(parameter.type() + ":" + parameter.name());
            }
            java.util.Collections.sort(names);
            key.append('?').append(String.join(",", names));
        }
        return key.toString();
    }

    public void clearDedupeCache() {
        seenRequests.clear();
    }

    /**
     * Continues record numbering after results restored from the project, so
     * numbers stay unique across Burp restarts.
     */
    public void resumeIndexingAfter(int highestRestoredIndex) {
        recordCounter.updateAndGet(current -> Math.max(current, highestRestoredIndex));
    }

    // -- execution -----------------------------------------------------------

    private void runAndPublish(HttpRequestResponse baseline, String source) {
        try {
            AuthTestRecord record = run(baseline, source);
            records.add(record);
            statusListener.run();
        } catch (Exception e) {
            api.logging().logToError("[auth-check] Test failed for " + baseline.request().url(), e);
        }
    }

    /** Replays one request as every variant and judges the results. */
    public AuthTestRecord run(HttpRequestResponse baseline, String source) {
        Settings settings = configuration.settings();
        HttpResponse baseResponse = baseline.hasResponse() ? baseline.response() : null;
        Map<String, VariantResult> results = new LinkedHashMap<>();

        boolean publicEndpoint = false;
        if (settings.testUnauthenticated()) {
            VariantResult result = testUnauthenticated(baseline.request(), baseResponse);
            results.put(Identity.UNAUTHENTICATED_KEY, result);
            publicEndpoint = result.verdict() == Verdict.BYPASSED;
        }

        for (Identity identity : configuration.enabledIdentities()) {
            results.put(identity.id(), testIdentity(identity, baseline.request(), baseResponse));
        }

        List<String> notes = new ArrayList<>();
        if (baseResponse == null) {
            notes.add("baseline had no response");
        } else if (!ResponseAnalyser.isSuccess(baseResponse.statusCode())) {
            notes.add("baseline HTTP " + baseResponse.statusCode() + " - not an authorised-access reference");
        }
        if (publicEndpoint) {
            notes.add("endpoint appears public - unauthenticated access succeeded, so identity results prove nothing");
        }

        return new AuthTestRecord(recordCounter.incrementAndGet(), source, baseline, results,
                publicEndpoint, String.join("; ", notes));
    }

    private VariantResult testUnauthenticated(HttpRequest base, HttpResponse baseResponse) {
        String label = "Unauthenticated";
        try {
            HttpRequest stripped = mutator.applyUnauthenticated(base);
            HttpRequestResponse exchange = send(stripped);
            ResponseAnalyser.Analysis analysis = analyser.analyse(baseResponse, responseOf(exchange));
            return new VariantResult(Identity.UNAUTHENTICATED_KEY, label, analysis.verdict(),
                    analysis.similarity(), analysis.detail(), false, store(exchange));
        } catch (Exception e) {
            return VariantResult.failed(Identity.UNAUTHENTICATED_KEY, label, Verdict.ERROR,
                    "Replay failed: " + e);
        }
    }

    private VariantResult testIdentity(Identity identity, HttpRequest base, HttpResponse baseResponse) {
        String key = identity.id();
        String label = identity.name();
        try {
            AuthMaterial material = sessionManager.materialFor(identity);
            if (material == null) {
                return VariantResult.failed(key, label, Verdict.AUTH_FAILED,
                        "Could not establish a session for this identity. "
                        + sessionManager.statusFor(identity));
            }

            HttpRequest request = mutator.applyIdentity(base, identity, material);
            HttpRequestResponse exchange = send(request);
            HttpResponse response = responseOf(exchange);
            ResponseAnalyser.Analysis analysis = analyser.analyse(baseResponse, response);

            // The session may have died between logging in and replaying -- the
            // whole point of this extension. Decide whether to rebuild it.
            boolean expired = sessionManager.isDefinitelyExpired(identity, response);
            boolean speculative = !expired
                    && analysis.verdict() == Verdict.ENFORCED
                    && sessionManager.shouldReauthAfterDenial(identity);

            if (expired || speculative) {
                String previousFingerprint = material.fingerprint();
                sessionManager.invalidate(identity);
                AuthMaterial refreshed = sessionManager.materialFor(identity);
                if (refreshed == null) {
                    return new VariantResult(key, label, Verdict.AUTH_FAILED, analysis.similarity(),
                            (expired ? "Session had expired" : "Response was denied")
                            + " and re-authentication failed: " + sessionManager.statusFor(identity),
                            true, store(exchange));
                }
                if (expired || !refreshed.fingerprint().equals(previousFingerprint)) {
                    HttpRequest retry = mutator.applyIdentity(base, identity, refreshed);
                    HttpRequestResponse retryExchange = send(retry);
                    ResponseAnalyser.Analysis retryAnalysis =
                            analyser.analyse(baseResponse, responseOf(retryExchange));
                    String reason = expired
                            ? "Session had expired; re-authenticated and replayed. "
                            : "Response was denied and the session could not be proven alive; "
                              + "re-authenticated and replayed. ";
                    return new VariantResult(key, label, retryAnalysis.verdict(), retryAnalysis.similarity(),
                            reason + retryAnalysis.detail(), true, store(retryExchange));
                }
                // Same credentials came back, so the denial was genuine.
                return new VariantResult(key, label, analysis.verdict(), analysis.similarity(),
                        analysis.detail() + " (re-authentication returned the same session, "
                        + "so this denial is authorisation, not expiry)",
                        true, store(exchange));
            }

            // State what was applied, so a replay that is missing it on the wire
            // is visibly the mutator's or Burp's problem, not the script's.
            return new VariantResult(key, label, analysis.verdict(), analysis.similarity(),
                    analysis.detail() + "\n\nAuth applied to this replay: " + material.summary(),
                    false, store(exchange));
        } catch (Exception e) {
            return VariantResult.failed(key, label, Verdict.ERROR, "Replay failed: " + e);
        }
    }

    private HttpRequestResponse send(HttpRequest request) {
        Settings settings = configuration.settings();
        RequestOptions options = RequestOptions.requestOptions()
                .withRedirectionMode(settings.followRedirectsOnReplay()
                        ? RedirectionMode.ALWAYS : RedirectionMode.NEVER)
                .withResponseTimeout(settings.responseTimeoutMillis());
        return api.http().sendRequest(request, options);
    }

    private static HttpResponse responseOf(HttpRequestResponse exchange) {
        return exchange != null && exchange.hasResponse() ? exchange.response() : null;
    }

    /** Keeps replayed exchanges on disk rather than in heap. */
    private static HttpRequestResponse store(HttpRequestResponse exchange) {
        return exchange == null ? null : exchange.copyToTempFile();
    }

    // -- status --------------------------------------------------------------

    public int queueDepth() {
        return autoExecutor.getQueue().size();
    }

    public int droppedCount() {
        return droppedCount.get();
    }

    public int skippedCount() {
        return skippedCount.get();
    }

    public void resetCounters() {
        droppedCount.set(0);
        skippedCount.set(0);
    }

    public void shutdown() {
        autoExecutor.shutdownNow();
        manualExecutor.shutdownNow();
    }
}
