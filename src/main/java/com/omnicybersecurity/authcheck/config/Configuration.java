package com.omnicybersecurity.authcheck.config;

import com.omnicybersecurity.authcheck.model.Identity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Live extension state: the settings plus the identity roster, with change
 * notification so the results table, the session-handling actions and the
 * project file all stay in step.
 *
 * <p>The identity list is copy-on-write because engine workers iterate it while
 * the UI edits it.
 */
public final class Configuration {

    private final Settings settings = new Settings();
    private final List<Identity> identities = new CopyOnWriteArrayList<>();
    private final ConfigStore store;

    private final List<Runnable> identityListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> settingsListeners = new CopyOnWriteArrayList<>();

    public Configuration(ConfigStore store) {
        this.store = store;
    }

    public Settings settings() {
        return settings;
    }

    /** Live view of all identities, enabled or not. */
    public List<Identity> identities() {
        return identities;
    }

    public List<Identity> enabledIdentities() {
        List<Identity> out = new ArrayList<>();
        for (Identity identity : identities) {
            if (identity.enabled()) {
                out.add(identity);
            }
        }
        return out;
    }

    public Identity identityById(String id) {
        for (Identity identity : identities) {
            if (identity.id().equals(id)) {
                return identity;
            }
        }
        return null;
    }

    public void load() {
        List<Identity> loaded = new ArrayList<>();
        store.load(settings, loaded);
        identities.clear();
        identities.addAll(loaded);
    }

    public void save() {
        store.save(settings, new ArrayList<>(identities));
    }

    public void add(Identity identity) {
        identities.add(identity);
        identitiesChanged();
    }

    public void remove(Identity identity) {
        identities.remove(identity);
        identitiesChanged();
    }

    public void move(int fromIndex, int toIndex) {
        if (fromIndex < 0 || toIndex < 0 || fromIndex >= identities.size() || toIndex >= identities.size()) {
            return;
        }
        List<Identity> copy = new ArrayList<>(identities);
        copy.add(toIndex, copy.remove(fromIndex));
        identities.clear();
        identities.addAll(copy);
        identitiesChanged();
    }

    /** Call after adding, removing, renaming or enabling/disabling identities. */
    public void identitiesChanged() {
        save();
        identityListeners.forEach(Runnable::run);
    }

    public void settingsChanged() {
        save();
        settingsListeners.forEach(Runnable::run);
    }

    public void onIdentitiesChanged(Runnable listener) {
        identityListeners.add(listener);
    }

    public void onSettingsChanged(Runnable listener) {
        settingsListeners.add(listener);
    }
}
