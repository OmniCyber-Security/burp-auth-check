package com.omnicybersecurity.authcheck.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;
import com.omnicybersecurity.authcheck.model.VariantResult;
import com.omnicybersecurity.authcheck.model.Verdict;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stores tested requests and responses -- baseline and every identity's replay --
 * in the Burp project, next to the auth scripts that produced the sessions.
 *
 * <p>Also keeps the traffic each auth script generated while logging in, so a
 * finding can be reproduced later: the script, the credentials it read, the login
 * exchange it performed, and the replay it produced are all in the same project.
 *
 * <p>Writes happen on a dedicated thread. Serialising bodies is not free and the
 * engine's workers should be testing, not writing; if persistence falls behind,
 * writes are shed and counted rather than allowed to throttle testing.
 */
public final class ResultsRepository {

    private static final String ROOT_KEY = "omnicyber.authcheck.results";
    private static final String TRANSCRIPTS_KEY = "omnicyber.authcheck.authtraffic";
    private static final String ORDER_KEY = "order";
    private static final String VARIANTS_KEY = "variants";
    private static final String PROBE_KEY = "omnicyber.authcheck.probe";

    private final MontoyaApi api;
    private final Settings settings;
    private final ExecutorService writer;
    private final AtomicInteger droppedWrites = new AtomicInteger();

    /** Keys currently held in the project, oldest first. Writer thread only. */
    private final Deque<String> persistedKeys = new ArrayDeque<>();

    /**
     * Whether mutating a child fetched with {@code getChildObject} reaches the
     * project. Burp's implementation returns live views, but that is not stated
     * in the API contract, so it is probed once and the slower re-attach path is
     * used if the probe fails.
     */
    private boolean liveChildWrites = true;
    private PersistedObject resultsRoot;
    private boolean resultsDirty;

    public ResultsRepository(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
        this.writer = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1_000),
                task -> {
                    Thread thread = new Thread(task, "auth-check-persist");
                    thread.setDaemon(true);
                    return thread;
                },
                (task, executor) -> droppedWrites.incrementAndGet());
    }

    // -- lifecycle -----------------------------------------------------------

    /** Probes the persistence semantics and returns the stored records. */
    public List<AuthTestRecord> load() {
        liveChildWrites = probeLiveChildWrites();
        if (!liveChildWrites) {
            api.logging().logToOutput("[auth-check] Project child objects are not live; "
                    + "results will be written with periodic full rewrites.");
        }

        PersistedObject root = resultsRoot();
        List<AuthTestRecord> loaded = new ArrayList<>();
        for (String key : orderedKeys(root)) {
            PersistedObject node = root.getChildObject(key);
            if (node == null) {
                continue;
            }
            try {
                loaded.add(readRecord(node));
                persistedKeys.addLast(key);
            } catch (Exception e) {
                api.logging().logToError("[auth-check] Could not read stored result '" + key + "': " + e);
            }
        }
        return loaded;
    }

    /** The login traffic stored for an identity, oldest exchange first. */
    public List<HttpRequestResponse> loadAuthTranscript(String identityId) {
        PersistedObject store = api.persistence().extensionData().getChildObject(TRANSCRIPTS_KEY);
        if (store == null) {
            return List.of();
        }
        PersistedObject node = store.getChildObject(identityId);
        if (node == null) {
            return List.of();
        }
        PersistedList<HttpRequestResponse> exchanges = node.getHttpRequestResponseList("exchanges");
        return exchanges == null ? List.of() : List.copyOf(exchanges);
    }

    // -- writing -------------------------------------------------------------

    /** Queues a record for storage. Returns immediately. */
    public void append(AuthTestRecord record) {
        if (!settings.persistResults() || settings.maxPersistedRecords() == 0) {
            return;
        }
        if (settings.persistOnlyInteresting() && !isInteresting(record)) {
            return;
        }
        writer.execute(() -> {
            try {
                writeRecord(record);
            } catch (Exception e) {
                api.logging().logToError("[auth-check] Could not store result #" + record.index(), e);
            }
        });
    }

    /** Queues the login traffic for an identity, replacing anything stored. */
    public void storeAuthTranscript(String identityId, List<HttpRequestResponse> exchanges) {
        if (!settings.persistResults() || exchanges == null || exchanges.isEmpty()) {
            return;
        }
        List<HttpRequestResponse> copy = List.copyOf(exchanges);
        writer.execute(() -> {
            try {
                PersistedObject root = api.persistence().extensionData();
                PersistedObject store = root.getChildObject(TRANSCRIPTS_KEY);
                if (store == null) {
                    store = PersistedObject.persistedObject();
                    root.setChildObject(TRANSCRIPTS_KEY, store);
                    store = liveChildWrites ? root.getChildObject(TRANSCRIPTS_KEY) : store;
                }
                PersistedObject node = PersistedObject.persistedObject();
                node.setLong("recordedAt", System.currentTimeMillis());
                PersistedList<HttpRequestResponse> list = PersistedList.persistedHttpRequestResponseList();
                list.addAll(copy);
                node.setHttpRequestResponseList("exchanges", list);
                store.setChildObject(identityId, node);
                if (!liveChildWrites) {
                    root.setChildObject(TRANSCRIPTS_KEY, store);
                }
            } catch (Exception e) {
                api.logging().logToError("[auth-check] Could not store login traffic for " + identityId, e);
            }
        });
    }

    /** Removes every stored result. Login traffic is kept with the scripts. */
    public void clear() {
        writer.execute(() -> {
            PersistedObject root = api.persistence().extensionData();
            root.deleteChildObject(ROOT_KEY);
            persistedKeys.clear();
            resultsRoot = null;
            resultsDirty = false;
        });
    }

    /** Removes stored login traffic for an identity that has been deleted. */
    public void forgetIdentity(String identityId) {
        writer.execute(() -> {
            PersistedObject root = api.persistence().extensionData();
            PersistedObject store = root.getChildObject(TRANSCRIPTS_KEY);
            if (store == null) {
                return;
            }
            store.deleteChildObject(identityId);
            if (!liveChildWrites) {
                // The fetched child was a detached copy, so the deletion only
                // takes effect once the copy is written back.
                root.setChildObject(TRANSCRIPTS_KEY, store);
            }
        });
    }

    public int droppedWrites() {
        return droppedWrites.get();
    }

    /** Flushes pending work and stops the writer. */
    public void shutdown() {
        writer.execute(this::flush);
        writer.shutdown();
        try {
            if (!writer.awaitTermination(10, TimeUnit.SECONDS)) {
                writer.shutdownNow();
            }
        } catch (InterruptedException e) {
            writer.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // -- writer-thread internals --------------------------------------------

    private void writeRecord(AuthTestRecord record) {
        PersistedObject root = resultsRoot();
        String key = key(record.index());

        PersistedObject node = PersistedObject.persistedObject();
        node.setInteger("index", record.index());
        node.setLong("timestamp", record.timestamp().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli());
        node.setString("source", record.source());
        node.setString("note", record.note());
        node.setBoolean("publicEndpoint", record.publicEndpoint());
        if (record.baseline() != null) {
            node.setHttpRequestResponse("baseline", record.baseline());
        }

        PersistedObject variants = PersistedObject.persistedObject();
        PersistedList<String> variantOrder = PersistedList.persistedStringList();
        for (Map.Entry<String, VariantResult> entry : record.results().entrySet()) {
            VariantResult result = entry.getValue();
            PersistedObject variant = PersistedObject.persistedObject();
            variant.setString("label", result.label());
            variant.setString("verdict", result.verdict().name());
            variant.setString("detail", result.detail());
            variant.setLong("similarity", Math.round(result.similarity() * 10_000d));
            variant.setBoolean("reAuthed", result.reAuthed());
            if (result.exchange() != null) {
                variant.setHttpRequestResponse("exchange", result.exchange());
            }
            variants.setChildObject(entry.getKey(), variant);
            variantOrder.add(entry.getKey());
        }
        variants.setStringList(ORDER_KEY, variantOrder);
        node.setChildObject(VARIANTS_KEY, variants);

        root.setChildObject(key, node);
        persistedKeys.addLast(key);

        // Enforce the storage cap independently of the in-memory cap, so a long
        // engagement does not grow the project file without bound.
        while (persistedKeys.size() > settings.maxPersistedRecords()) {
            String oldest = persistedKeys.pollFirst();
            if (oldest != null) {
                root.deleteChildObject(oldest);
            }
        }
        rewriteOrder(root);
        markDirty(root);
    }

    private AuthTestRecord readRecord(PersistedObject node) {
        Integer index = node.getInteger("index");
        Long timestamp = node.getLong("timestamp");
        LocalDateTime when = timestamp == null
                ? LocalDateTime.now()
                : LocalDateTime.ofInstant(Instant.ofEpochMilli(timestamp), ZoneId.systemDefault());

        Map<String, VariantResult> results = new LinkedHashMap<>();
        PersistedObject variants = node.getChildObject(VARIANTS_KEY);
        if (variants != null) {
            for (String variantKey : orderedKeys(variants)) {
                PersistedObject variant = variants.getChildObject(variantKey);
                if (variant == null) {
                    continue;
                }
                Long similarity = variant.getLong("similarity");
                Boolean reAuthed = variant.getBoolean("reAuthed");
                results.put(variantKey, new VariantResult(
                        variantKey,
                        orEmpty(variant.getString("label")),
                        parseVerdict(variant.getString("verdict")),
                        similarity == null ? 0d : similarity / 10_000d,
                        orEmpty(variant.getString("detail")),
                        reAuthed != null && reAuthed,
                        variant.getHttpRequestResponse("exchange")));
            }
        }

        Boolean publicEndpoint = node.getBoolean("publicEndpoint");
        return new AuthTestRecord(
                index == null ? 0 : index,
                when,
                orEmpty(node.getString("source")),
                node.getHttpRequestResponse("baseline"),
                results,
                publicEndpoint != null && publicEndpoint,
                orEmpty(node.getString("note")));
    }

    /** The results container, fetched live or held locally in fallback mode. */
    private PersistedObject resultsRoot() {
        if (resultsRoot != null && !liveChildWrites) {
            return resultsRoot;
        }
        PersistedObject root = api.persistence().extensionData();
        PersistedObject existing = root.getChildObject(ROOT_KEY);
        if (existing == null) {
            existing = PersistedObject.persistedObject();
            root.setChildObject(ROOT_KEY, existing);
            if (liveChildWrites) {
                PersistedObject fetched = root.getChildObject(ROOT_KEY);
                if (fetched != null) {
                    existing = fetched;
                }
            }
        }
        resultsRoot = existing;
        return existing;
    }

    /** In fallback mode the container has to be re-attached for writes to land. */
    private void markDirty(PersistedObject root) {
        if (liveChildWrites) {
            return;
        }
        resultsDirty = true;
        // The writer is single-threaded, so flushing when the queue drains keeps
        // the cost to one rewrite per burst rather than one per record.
        if (((ThreadPoolExecutor) writer).getQueue().isEmpty()) {
            flush();
        }
    }

    private void flush() {
        if (resultsDirty && resultsRoot != null) {
            api.persistence().extensionData().setChildObject(ROOT_KEY, resultsRoot);
            resultsDirty = false;
        }
    }

    private void rewriteOrder(PersistedObject root) {
        PersistedList<String> order = PersistedList.persistedStringList();
        order.addAll(persistedKeys);
        root.setStringList(ORDER_KEY, order);
    }

    /** Stored order first, then anything else present, so nothing is lost. */
    private static List<String> orderedKeys(PersistedObject container) {
        List<String> keys = new ArrayList<>();
        PersistedList<String> order = container.getStringList(ORDER_KEY);
        if (order != null) {
            keys.addAll(order);
        }
        List<String> present = new ArrayList<>(container.childObjectKeys());
        java.util.Collections.sort(present);
        for (String key : present) {
            if (!keys.contains(key)) {
                keys.add(key);
            }
        }
        keys.removeIf(key -> !container.childObjectKeys().contains(key));
        return keys;
    }

    private boolean probeLiveChildWrites() {
        try {
            PersistedObject root = api.persistence().extensionData();
            root.setChildObject(PROBE_KEY, PersistedObject.persistedObject());
            PersistedObject fetched = root.getChildObject(PROBE_KEY);
            if (fetched == null) {
                return false;
            }
            fetched.setString("probe", "live");
            PersistedObject reread = root.getChildObject(PROBE_KEY);
            boolean live = reread != null && "live".equals(reread.getString("probe"));
            root.deleteChildObject(PROBE_KEY);
            return live;
        } catch (Exception e) {
            api.logging().logToError("[auth-check] Persistence probe failed; assuming full rewrites", e);
            return false;
        }
    }

    private static boolean isInteresting(AuthTestRecord record) {
        return record.worstVerdict().severity() >= Verdict.NEEDS_REVIEW.severity();
    }

    private static Verdict parseVerdict(String name) {
        if (name == null) {
            return Verdict.NOT_TESTED;
        }
        try {
            return Verdict.valueOf(name);
        } catch (IllegalArgumentException e) {
            return Verdict.NOT_TESTED;
        }
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String key(int index) {
        return String.format("r%08d", index);
    }
}
