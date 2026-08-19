package com.omnicybersecurity.authcheck.auth;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.omnicybersecurity.authcheck.model.AuthMaterial;
import com.omnicybersecurity.authcheck.model.Identity;
import com.omnicybersecurity.authcheck.model.ParamSpec;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns whatever an auth script returned into an {@link AuthMaterial}.
 *
 * <p>Scripts are written by testers under time pressure, so several shapes are
 * accepted:
 * <ul>
 *   <li>{@code AuthMaterial} or its builder -- used directly</li>
 *   <li>a {@code String} -- written to the identity's token header</li>
 *   <li>a {@code Map} with any of {@code headers}, {@code cookies},
 *       {@code params}, {@code removeHeaders}, {@code vars}</li>
 *   <li>a {@code Map} with none of those keys -- treated as headers</li>
 *   <li>an {@code HttpRequestResponse} -- its {@code Set-Cookie} cookies are
 *       adopted as the session</li>
 * </ul>
 */
public final class ScriptResultMapper {

    private static final Set<String> KNOWN_KEYS = Set.of(
            "headers", "header", "cookies", "cookie", "params", "parameters",
            "removeheaders", "remove", "vars", "var");

    private ScriptResultMapper() {
    }

    public static AuthMaterial map(Object result, Identity identity) {
        if (result == null) {
            return AuthMaterial.empty();
        }
        if (result instanceof AuthMaterial material) {
            return material;
        }
        if (result instanceof AuthMaterial.Builder builder) {
            return builder.build();
        }
        if (result instanceof CharSequence text) {
            return AuthMaterial.builder()
                    .header(identity.tokenHeaderName(), text.toString())
                    .build();
        }
        if (result instanceof HttpRequestResponse exchange) {
            return fromExchange(exchange);
        }
        if (result instanceof Map<?, ?> map) {
            return fromMap(map, identity);
        }
        throw new IllegalArgumentException("Auth script returned a "
                + result.getClass().getSimpleName()
                + "; expected a Map, a String, or an AuthMaterial. See the Help tab.");
    }

    private static AuthMaterial fromExchange(HttpRequestResponse exchange) {
        AuthMaterial.Builder builder = AuthMaterial.builder();
        if (exchange.hasResponse()) {
            for (Cookie cookie : exchange.response().cookies()) {
                builder.cookie(cookie.name(), cookie.value());
            }
        }
        return builder.build();
    }

    private static AuthMaterial fromMap(Map<?, ?> map, Identity identity) {
        AuthMaterial.Builder builder = AuthMaterial.builder();

        boolean recognised = false;
        for (Object key : map.keySet()) {
            if (key != null && KNOWN_KEYS.contains(key.toString().toLowerCase(java.util.Locale.ROOT))) {
                recognised = true;
                break;
            }
        }
        if (!recognised) {
            // Bare map of header names to values -- the most common shorthand.
            applyHeaders(builder, map);
            return builder.build();
        }

        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String key = entry.getKey().toString().toLowerCase(java.util.Locale.ROOT);
            Object value = entry.getValue();
            switch (key) {
                case "headers", "header" -> applyHeaders(builder, value);
                case "cookies", "cookie" -> applyCookies(builder, value);
                case "params", "parameters" -> applyParams(builder, value);
                case "removeheaders", "remove" -> applyRemovals(builder, value);
                case "vars", "var" -> applyVars(builder, value);
                default -> {
                    // Unknown key alongside known ones: treat as a header so a
                    // typo'd wrapper key still does something visible.
                    builder.header(entry.getKey().toString(), str(value));
                }
            }
        }
        return builder.build();
    }

    private static void applyHeaders(AuthMaterial.Builder builder, Object value) {
        if (value instanceof Map<?, ?> map) {
            map.forEach((k, v) -> builder.header(str(k), str(v)));
        } else if (value instanceof Collection<?> items) {
            for (Object item : items) {
                if (item instanceof HttpHeader header) {
                    builder.header(header.name(), header.value());
                } else {
                    String text = str(item);
                    int colon = text.indexOf(':');
                    if (colon > 0) {
                        builder.header(text.substring(0, colon).trim(), text.substring(colon + 1).trim());
                    }
                }
            }
        } else if (value != null) {
            String text = str(value);
            int colon = text.indexOf(':');
            if (colon > 0) {
                builder.header(text.substring(0, colon).trim(), text.substring(colon + 1).trim());
            }
        }
    }

    private static void applyCookies(AuthMaterial.Builder builder, Object value) {
        if (value instanceof Map<?, ?> map) {
            map.forEach((k, v) -> builder.cookie(str(k), str(v)));
        } else if (value instanceof Collection<?> items) {
            for (Object item : items) {
                if (item instanceof Cookie cookie) {
                    builder.cookie(cookie.name(), cookie.value());
                } else {
                    addCookiePair(builder, str(item));
                }
            }
        } else if (value != null) {
            // "a=1; b=2" -- the shape you get from copying a Cookie header.
            for (String part : str(value).split(";")) {
                addCookiePair(builder, part);
            }
        }
    }

    private static void addCookiePair(AuthMaterial.Builder builder, String pair) {
        int equals = pair.indexOf('=');
        if (equals > 0) {
            builder.cookie(pair.substring(0, equals).trim(), pair.substring(equals + 1).trim());
        }
    }

    private static void applyParams(AuthMaterial.Builder builder, Object value) {
        if (!(value instanceof Collection<?> items)) {
            throw new IllegalArgumentException(
                    "'params' must be a list of maps like [type: 'BODY', name: 'csrf', value: token]");
        }
        for (Object item : items) {
            if (item instanceof ParamSpec spec) {
                builder.param(spec);
            } else if (item instanceof Map<?, ?> map) {
                Object type = firstOf(map, "type");
                Object name = firstOf(map, "name");
                Object paramValue = firstOf(map, "value");
                if (type == null || name == null) {
                    throw new IllegalArgumentException("Each param needs 'type' and 'name': " + map);
                }
                builder.param(ParamSpec.of(str(type), str(name), str(paramValue)));
            } else {
                throw new IllegalArgumentException("Unsupported param entry: " + item);
            }
        }
    }

    private static void applyRemovals(AuthMaterial.Builder builder, Object value) {
        if (value instanceof Collection<?> items) {
            for (Object item : items) {
                builder.removeHeader(str(item));
            }
        } else if (value != null) {
            for (String part : str(value).split(",")) {
                builder.removeHeader(part.trim());
            }
        }
    }

    private static void applyVars(AuthMaterial.Builder builder, Object value) {
        if (value instanceof Map<?, ?> map) {
            map.forEach((k, v) -> builder.var(str(k), str(v)));
        }
    }

    private static Object firstOf(Map<?, ?> map, String key) {
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() != null && entry.getKey().toString().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static String str(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof List<?> list && !list.isEmpty()) {
            return String.valueOf(list.get(0));
        }
        return String.valueOf(value);
    }
}
