package com.omnicybersecurity.authcheck.support;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * An in-memory stand-in for a Burp project's extension data.
 *
 * <p>{@code PersistedObject.persistedObject()} and friends are static interface
 * methods that delegate to a factory Burp installs at runtime, so persistence
 * code cannot run outside Burp at all unless that factory is provided. The
 * factory field is public and mutable, so tests install their own and exercise
 * the real {@code ConfigStore} and {@code ResultsRepository} code paths rather
 * than a reimplementation of them.
 *
 * <p>The API does not state whether a child fetched with {@code getChildObject}
 * is a live view or a copy, and the extension supports both. {@code liveChildren}
 * selects which semantics to model, so both branches are covered.
 */
public final class FakePersistence implements AutoCloseable {

    private final MontoyaObjectFactory previousFactory;
    private final PersistedObject extensionData;
    private final boolean liveChildren;

    private FakePersistence(boolean liveChildren) {
        this.liveChildren = liveChildren;
        this.previousFactory = ObjectFactoryLocator.FACTORY;
        ObjectFactoryLocator.FACTORY = factoryProxy(liveChildren);
        this.extensionData = FakeObject.create(liveChildren);
    }

    /** Installs a factory whose child objects behave as live views. */
    public static FakePersistence installLive() {
        return new FakePersistence(true);
    }

    /** Installs a factory whose child objects behave as detached copies. */
    public static FakePersistence installCopying() {
        return new FakePersistence(false);
    }

    public boolean liveChildren() {
        return liveChildren;
    }

    public PersistedObject extensionData() {
        return extensionData;
    }

    /** A MontoyaApi whose persistence and logging work; everything else throws. */
    public MontoyaApi api() {
        Logging logging = (Logging) Proxy.newProxyInstance(
                FakePersistence.class.getClassLoader(), new Class<?>[] { Logging.class },
                (proxy, method, args) -> method.getReturnType() == PrintStream.class
                        ? new PrintStream(OutputStream.nullOutputStream()) : null);

        Persistence persistence = (Persistence) Proxy.newProxyInstance(
                FakePersistence.class.getClassLoader(), new Class<?>[] { Persistence.class },
                (proxy, method, args) -> {
                    if ("extensionData".equals(method.getName())) {
                        return extensionData;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });

        return (MontoyaApi) Proxy.newProxyInstance(
                FakePersistence.class.getClassLoader(), new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "persistence" -> persistence;
                    case "logging" -> logging;
                    default -> throw new UnsupportedOperationException(
                            "Test must not reach MontoyaApi." + method.getName() + "()");
                });
    }

    @Override
    public void close() {
        ObjectFactoryLocator.FACTORY = previousFactory;
    }

    private static MontoyaObjectFactory factoryProxy(boolean liveChildren) {
        return (MontoyaObjectFactory) Proxy.newProxyInstance(
                FakePersistence.class.getClassLoader(), new Class<?>[] { MontoyaObjectFactory.class },
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("persistedObject".equals(name)) {
                        return FakeObject.create(liveChildren);
                    }
                    if (name.startsWith("persisted") && name.endsWith("List")) {
                        return fakeList();
                    }
                    throw new UnsupportedOperationException(
                            "FakePersistence does not provide " + name + "()");
                });
    }

    /** A PersistedList backed by a plain ArrayList. */
    @SuppressWarnings("unchecked")
    private static PersistedList<Object> fakeList() {
        List<Object> backing = new ArrayList<>();
        return (PersistedList<Object>) Proxy.newProxyInstance(
                FakePersistence.class.getClassLoader(), new Class<?>[] { PersistedList.class },
                (proxy, method, args) -> {
                    if ("equals".equals(method.getName())) {
                        return proxy == args[0];
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    return method.invoke(backing, args);
                });
    }

    /**
     * Typed key/value store behind a PersistedObject proxy. Method names follow a
     * strict {@code get/set/delete<Type>} plus {@code <type>Keys} shape, so one
     * generic handler covers the whole interface.
     */
    private static final class FakeObject implements InvocationHandler {

        private final Map<String, Map<String, Object>> byType = new LinkedHashMap<>();
        private final boolean liveChildren;

        private FakeObject(boolean liveChildren) {
            this.liveChildren = liveChildren;
        }

        static PersistedObject create(boolean liveChildren) {
            return (PersistedObject) Proxy.newProxyInstance(
                    FakePersistence.class.getClassLoader(),
                    new Class<?>[] { PersistedObject.class },
                    new FakeObject(liveChildren));
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            switch (name) {
                case "equals" -> {
                    return proxy == args[0];
                }
                case "hashCode" -> {
                    return System.identityHashCode(proxy);
                }
                case "toString" -> {
                    return "FakePersistedObject" + byType;
                }
                default -> { }
            }

            if (name.endsWith("Keys")) {
                String type = capitalise(name.substring(0, name.length() - "Keys".length()));
                return new LinkedHashSet<>(map(type).keySet());
            }
            if (name.startsWith("get")) {
                String type = name.substring(3);
                Object value = map(type).get(args[0]);
                return "ChildObject".equals(type) ? viewOf(value) : value;
            }
            if (name.startsWith("set")) {
                String type = name.substring(3);
                Object value = "ChildObject".equals(type) ? storedForm(args[1]) : args[1];
                map(type).put((String) args[0], value);
                return null;
            }
            if (name.startsWith("delete")) {
                map(name.substring("delete".length())).remove(args[0]);
                return null;
            }
            throw new UnsupportedOperationException("FakePersistence does not implement " + name + "()");
        }

        /** Copying mode snapshots on write, so later mutation of the caller's
         *  reference must not be visible through the store. */
        private Object storedForm(Object child) {
            return liveChildren ? child : deepCopy(child);
        }

        /** Copying mode also snapshots on read, so mutating what you read back
         *  does not reach the store either. */
        private Object viewOf(Object child) {
            return liveChildren ? child : deepCopy(child);
        }

        private Object deepCopy(Object child) {
            if (child == null) {
                return null;
            }
            FakeObject source = (FakeObject) Proxy.getInvocationHandler(child);
            FakeObject copy = new FakeObject(liveChildren);
            source.byType.forEach((type, entries) -> {
                Map<String, Object> target = copy.map(type);
                entries.forEach((key, value) -> target.put(key,
                        "ChildObject".equals(type) ? copy.deepCopy(value) : copyValue(value)));
            });
            return Proxy.newProxyInstance(FakePersistence.class.getClassLoader(),
                    new Class<?>[] { PersistedObject.class }, copy);
        }

        /** Lists are mutable, so they are snapshotted along with the object. */
        @SuppressWarnings("unchecked")
        private static Object copyValue(Object value) {
            if (value instanceof PersistedList<?> list) {
                PersistedList<Object> copy = fakeList();
                copy.addAll((List<Object>) list);
                return copy;
            }
            return value;
        }

        private Map<String, Object> map(String type) {
            return byType.computeIfAbsent(type, key -> new LinkedHashMap<>());
        }

        private static String capitalise(String value) {
            return value.substring(0, 1).toUpperCase(Locale.ROOT) + value.substring(1);
        }
    }
}
