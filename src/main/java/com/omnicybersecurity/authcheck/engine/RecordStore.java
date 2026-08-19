package com.omnicybersecurity.authcheck.engine;

import com.omnicybersecurity.authcheck.config.ResultsRepository;
import com.omnicybersecurity.authcheck.config.Settings;
import com.omnicybersecurity.authcheck.model.AuthTestRecord;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Holds completed test records for the results table, capped so a long
 * engagement cannot exhaust heap. Listeners are notified on the calling thread;
 * the engine always publishes onto the Swing event thread.
 */
public final class RecordStore {

    private final List<AuthTestRecord> records = new ArrayList<>();
    private final List<Consumer<AuthTestRecord>> addListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> resetListeners = new CopyOnWriteArrayList<>();
    private final Settings settings;
    private final ResultsRepository repository;
    private int findingsCount;

    public RecordStore(Settings settings, ResultsRepository repository) {
        this.settings = settings;
        this.repository = repository;
    }

    /**
     * Seeds the store from records read back out of the Burp project, without
     * writing them straight back.
     *
     * @return the highest record number restored, so numbering continues
     */
    public int restore(List<AuthTestRecord> restored) {
        int highest = 0;
        synchronized (this) {
            for (AuthTestRecord record : restored) {
                records.add(record);
                if (record.hasFinding()) {
                    findingsCount++;
                }
                highest = Math.max(highest, record.index());
            }
        }
        resetListeners.forEach(Runnable::run);
        return highest;
    }

    /** Rows with at least one bypass, tracked incrementally for the status line. */
    public synchronized int findingsCount() {
        return findingsCount;
    }

    public synchronized int size() {
        return records.size();
    }

    public synchronized AuthTestRecord get(int index) {
        return index >= 0 && index < records.size() ? records.get(index) : null;
    }

    public synchronized List<AuthTestRecord> snapshot() {
        return new ArrayList<>(records);
    }

    /** Appends a record, trimming the oldest if the cap is exceeded. */
    public void add(AuthTestRecord record) {
        boolean trimmed;
        synchronized (this) {
            records.add(record);
            if (record.hasFinding()) {
                findingsCount++;
            }
            trimmed = records.size() > settings.maxRecords();
            if (trimmed) {
                int excess = records.size() - settings.maxRecords();
                List<AuthTestRecord> evicted = records.subList(0, excess);
                for (AuthTestRecord dropped : evicted) {
                    if (dropped.hasFinding()) {
                        findingsCount--;
                    }
                }
                evicted.clear();
            }
        }
        repository.append(record);
        if (trimmed) {
            // Row indices all shifted, so the table has to reload wholesale.
            resetListeners.forEach(Runnable::run);
        } else {
            addListeners.forEach(listener -> listener.accept(record));
        }
    }

    public void clear() {
        synchronized (this) {
            records.clear();
            findingsCount = 0;
        }
        repository.clear();
        resetListeners.forEach(Runnable::run);
    }

    public void onAdded(Consumer<AuthTestRecord> listener) {
        addListeners.add(listener);
    }

    public void onReset(Runnable listener) {
        resetListeners.add(listener);
    }
}
