package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.MontoyaApi;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.Identity;
import groovy.lang.Binding;
import groovy.lang.GroovyClassLoader;
import groovy.lang.Script;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.ImportCustomizer;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Compiles and runs the tester's Groovy auth scripts.
 *
 * <p>Scripts are compiled once and cached by source hash, then run with a fresh
 * {@link Binding} per invocation. Every run is bounded by a timeout so a script
 * that hangs on a dead login endpoint cannot wedge the engine's worker threads.
 */
public final class AuthScriptEngine {

    private static final int MAX_CACHED_SCRIPTS = 64;

    private final MontoyaApi api;
    private final Settings settings;

    private final Map<String, Class<?>> compiled = new ConcurrentHashMap<>();
    private final ExecutorService runner;
    private volatile GroovyClassLoader loader;

    public AuthScriptEngine(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
        this.loader = newLoader();
        AtomicInteger counter = new AtomicInteger();
        this.runner = Executors.newCachedThreadPool(task -> {
            Thread thread = new Thread(task, "auth-check-script-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    private GroovyClassLoader newLoader() {
        CompilerConfiguration config = new CompilerConfiguration();
        ImportCustomizer imports = new ImportCustomizer();
        imports.addImports(
                "burp.api.montoya.http.message.requests.HttpRequest",
                "burp.api.montoya.http.message.responses.HttpResponse",
                "burp.api.montoya.http.message.HttpRequestResponse",
                "burp.api.montoya.http.message.HttpHeader",
                "burp.api.montoya.http.HttpService",
                "burp.api.montoya.core.ByteArray",
                "com.omnicybersecurity.authcheck.model.AuthMaterial",
                "com.omnicybersecurity.authcheck.model.ParamSpec");
        imports.addStarImports("groovy.json", "java.util.regex");
        config.addCompilationCustomizers(imports);
        // Gives the bindings real types, so an editor with the jar on its
        // classpath can complete creds./http./vars. and check signatures.
        config.setScriptBaseClass(AuthScriptBase.class.getName());
        // Scripts are the tester's own code running in their own Burp; the point
        // of the extension is to let them do whatever the target's login needs.
        return new GroovyClassLoader(AuthScriptEngine.class.getClassLoader(), config);
    }

    /**
     * Runs an identity's script and converts the result into auth material.
     *
     * @param identity the identity being authenticated
     * @param vars     persistent per-identity map, kept across refreshes so
     *                 refresh-token flows can stash state
     */
    public AuthOutcome authenticate(Identity identity, Map<String, String> vars) {
        ScriptLog log = new ScriptLog(api.logging(), identity.name());

        if (!identity.hasScript()) {
            // No script: the identity is driven purely by its static headers,
            // which the request mutator applies on every replay.
            log.info("No auth script configured; using static headers only.");
            return new AuthOutcome(true, AuthMaterial.empty(), log.text(), null);
        }

        // Everything the script declared about its credentials, read from the
        // source without running it. Checking here rather than in the UI means a
        // run started from a session-handling rule fails the same way, with the
        // same message, as one started from the Identities tab.
        ScriptParams declared = ScriptParamExtractor.extract(identity.authScript());
        Map<String, String> entered = identity.credentialsSnapshot();
        Map<String, String> credentials = declared.withDefaults(entered);
        AuthOutcome refusal = checkCredentials(declared, entered, credentials, log);
        if (refusal != null) {
            return refusal;
        }

        // One recording helper per attempt: the transcript belongs to this login,
        // not to every login the identity has ever performed.
        ScriptHttp scriptHttp = new ScriptHttp(api, settings, true);

        Binding binding = new Binding();
        binding.setVariable("api", api);
        binding.setVariable("http", scriptHttp);
        binding.setVariable("log", log);
        binding.setVariable("creds", credentials);
        binding.setVariable("vars", vars);
        binding.setVariable("identity", identity.name());
        binding.setVariable("material", AuthMaterial.builder());

        // Evict before the run starts: clearCache() closes the classloader, which
        // must not happen while a script from it is executing.
        if (compiled.size() >= MAX_CACHED_SCRIPTS) {
            clearCache();
        }

        int timeout = settings.scriptTimeoutSeconds();
        Future<Object> future = runner.submit(() -> execute(identity, binding));
        try {
            Object result = future.get(timeout, TimeUnit.SECONDS);
            AuthMaterial material = ScriptResultMapper.map(result, identity, log);
            if (material.isEmpty()) {
                // A script that returns nothing usable is nearly always a bug in
                // the script, and silently sending unauthenticated requests would
                // produce false "bypassed" findings.
                Object builderResult = binding.getVariable("material");
                if (builderResult instanceof AuthMaterial.Builder builder) {
                    AuthMaterial fromBuilder = builder.build();
                    if (!fromBuilder.isEmpty()) {
                        return new AuthOutcome(true, fromBuilder, log.text(), null,
                                scriptHttp.transcript());
                    }
                }
                if (identity.staticHeaderMap().isEmpty()) {
                    return new AuthOutcome(false, AuthMaterial.empty(), log.text(),
                            "Script produced no headers, cookies or params. Return a map such as "
                            + "[headers: ['Authorization': \"Bearer $token\"]].",
                            scriptHttp.transcript());
                }
            }
            // A blank token or session cookie is worse than none: the replay still
            // looks authenticated, so every verdict it produces is meaningless.
            if (!material.isEmpty() && !material.hasUsableValue()) {
                return new AuthOutcome(false, AuthMaterial.empty(), log.text(),
                        "Every value in the auth material is blank (" + material.blankValuedEntries()
                        + "). A lookup in the script probably missed -- check the names against the "
                        + "login response on the Login traffic tab.",
                        scriptHttp.transcript());
            }
            List<String> blank = material.blankValuedEntries();
            if (!blank.isEmpty()) {
                log.warn("Blank value(s) in the auth material: " + blank
                        + ". These are sent as empty, which usually means a lookup in the script missed.");
            }
            return new AuthOutcome(true, material, log.text(), null, scriptHttp.transcript());
        } catch (TimeoutException e) {
            future.cancel(true);
            log.error("Script timed out after " + timeout + "s");
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(),
                    "Auth script timed out after " + timeout + "s (see Settings to raise the limit).",
                    scriptHttp.transcript());
        } catch (CancellationException e) {
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(), "Auth script was cancelled.",
                    scriptHttp.transcript());
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(), "Interrupted while authenticating.",
                    scriptHttp.transcript());
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            log.error(cause.toString());
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(), describe(cause),
                    scriptHttp.transcript());
        }
    }

    /**
     * Refuses the run when the identity cannot satisfy what the script declared,
     * or null when it can. Failing before the first request is the point: a
     * login attempted with a missing credential either fails somewhere less
     * legible or, worse, succeeds as the wrong user.
     */
    private AuthOutcome checkCredentials(ScriptParams declared, Map<String, String> entered,
            Map<String, String> credentials, ScriptLog log) {
        if (!declared.problems().isEmpty()) {
            log.error("The params block is not valid.");
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(),
                    "The params block in this script is not valid:\n"
                    + bullets(declared.problems()));
        }

        List<String> missing = declared.missingRequired(credentials);
        if (!missing.isEmpty()) {
            log.error("Missing required credential(s): " + String.join(", ", missing));
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(),
                    "This identity is missing " + (missing.size() == 1 ? "a credential" : "credentials")
                    + " the script requires: " + String.join(", ", missing)
                    + ".\nFill " + (missing.size() == 1 ? "it" : "them")
                    + " in on the Credentials tab.");
        }

        List<String> invalid = declared.valueProblems(credentials);
        if (!invalid.isEmpty()) {
            log.error("Credential value(s) do not fit the declared type.");
            return new AuthOutcome(false, AuthMaterial.empty(), log.text(),
                    "This identity has credentials the script cannot use:\n" + bullets(invalid));
        }

        List<String> defaulted = declared.defaulted(entered);
        if (!defaulted.isEmpty()) {
            log.info("Using the script's default for: " + String.join(", ", defaulted));
        }
        return null;
    }

    private static String bullets(List<String> lines) {
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            sb.append("  - ").append(line).append('\n');
        }
        return sb.toString();
    }

    private Object execute(Identity identity, Binding binding) throws Exception {
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        GroovyClassLoader current = loader;
        Thread.currentThread().setContextClassLoader(current);
        try {
            Class<?> scriptClass = compile(identity, current);
            Script script = (Script) scriptClass.getDeclaredConstructor().newInstance();
            script.setBinding(binding);
            return script.run();
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    private Class<?> compile(Identity identity, GroovyClassLoader current) {
        String source = identity.authScript();
        String key = hash(source);
        Class<?> cached = compiled.get(key);
        if (cached != null) {
            return cached;
        }
        String name = "AuthScript_" + key.substring(0, 12);
        Class<?> parsed = current.parseClass(source, name + ".groovy");
        compiled.put(key, parsed);
        return parsed;
    }

    /** Drops compiled scripts and their classloader. Called on edits and unload. */
    public void clearCache() {
        GroovyClassLoader old = loader;
        loader = newLoader();
        compiled.clear();
        try {
            old.close();
        } catch (Exception ignored) {
            // Nothing useful to do if the loader will not close.
        }
    }

    /**
     * Compile-only check used by the "Check syntax" button. Also reports a
     * malformed {@code params} block, which compiles perfectly well -- it is
     * ordinary Groovy -- but would refuse every run.
     */
    public String validate(String source) {
        if (source == null || source.isBlank()) {
            return null;
        }
        try {
            loader.parseClass(source, "AuthScriptSyntaxCheck.groovy");
        } catch (Exception e) {
            return describe(e);
        }
        List<String> problems = ScriptParamExtractor.extract(source).problems();
        return problems.isEmpty()
                ? null
                : "The script compiles, but its params block is not valid:\n" + bullets(problems);
    }

    public void shutdown() {
        runner.shutdownNow();
        try {
            loader.close();
        } catch (Exception ignored) {
            // Extension is going away regardless.
        }
    }

    private static String describe(Throwable error) {
        StringWriter writer = new StringWriter();
        error.printStackTrace(new PrintWriter(writer));
        String message = error.getMessage() == null ? error.toString() : error.getMessage();
        // Groovy stack traces are long; lead with the message, keep the top frames.
        String[] lines = writer.toString().split("\\r?\\n");
        StringBuilder sb = new StringBuilder(message).append('\n');
        int kept = 0;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("at ") && kept < 6) {
                sb.append("    ").append(trimmed).append('\n');
                kept++;
            }
        }
        return sb.toString();
    }

    private static String hash(String source) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(source.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return Integer.toHexString(source.hashCode()) + "0000000000000000";
        }
    }
}
