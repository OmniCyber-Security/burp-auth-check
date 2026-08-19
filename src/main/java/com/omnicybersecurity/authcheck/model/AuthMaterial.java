package com.omnicybersecurity.authcheck.model;

import com.omnicybersecurity.authcheck.util.Text;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The concrete auth state for one identity: what to put on an outgoing request
 * so that it is sent as that user. Produced by an auth script (or by the
 * identity's static headers) and cached by the session manager.
 */
public final class AuthMaterial {

    private final Map<String, String> headers;
    private final Map<String, String> cookies;
    private final List<ParamSpec> params;
    private final List<String> removeHeaders;
    private final Map<String, String> vars;
    private final long obtainedAtMillis;

    private AuthMaterial(Map<String, String> headers, Map<String, String> cookies, List<ParamSpec> params,
            List<String> removeHeaders, Map<String, String> vars, long obtainedAtMillis) {
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        this.cookies = Collections.unmodifiableMap(new LinkedHashMap<>(cookies));
        this.params = List.copyOf(params);
        this.removeHeaders = List.copyOf(removeHeaders);
        this.vars = Collections.unmodifiableMap(new LinkedHashMap<>(vars));
        this.obtainedAtMillis = obtainedAtMillis;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static AuthMaterial empty() {
        return builder().build();
    }

    public Map<String, String> headers() {
        return headers;
    }

    public Map<String, String> cookies() {
        return cookies;
    }

    public List<ParamSpec> params() {
        return params;
    }

    public List<String> removeHeaders() {
        return removeHeaders;
    }

    /** Free-form values a script chose to surface (shown in the UI, not sent). */
    public Map<String, String> vars() {
        return vars;
    }

    public long obtainedAtMillis() {
        return obtainedAtMillis;
    }

    public long ageMillis() {
        return System.currentTimeMillis() - obtainedAtMillis;
    }

    public boolean isEmpty() {
        return headers.isEmpty() && cookies.isEmpty() && params.isEmpty();
    }

    /**
     * Names of entries whose value is blank. A blank session cookie or token is
     * almost always a script bug -- a lookup that missed -- and it is worse than
     * no material at all, because the replay still looks authenticated.
     */
    public List<String> blankValuedEntries() {
        List<String> blank = new ArrayList<>();
        headers.forEach((name, value) -> {
            if (Text.isBlank(value)) {
                blank.add("header " + name);
            }
        });
        cookies.forEach((name, value) -> {
            if (Text.isBlank(value)) {
                blank.add("cookie " + name);
            }
        });
        for (ParamSpec param : params) {
            if (Text.isBlank(param.value())) {
                blank.add("param " + param.name());
            }
        }
        return blank;
    }

    /** True when at least one header, cookie or param carries a real value. */
    public boolean hasUsableValue() {
        for (String value : headers.values()) {
            if (!Text.isBlank(value)) {
                return true;
            }
        }
        for (String value : cookies.values()) {
            if (!Text.isBlank(value)) {
                return true;
            }
        }
        for (ParamSpec param : params) {
            if (!Text.isBlank(param.value())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Identity of the material itself, ignoring when it was obtained. Used to
     * tell whether a re-authentication actually produced a new session -- if it
     * did not, there is no point replaying the request.
     */
    public String fingerprint() {
        StringBuilder sb = new StringBuilder();
        headers.forEach((k, v) -> sb.append("h:").append(k).append('=').append(v).append('\n'));
        cookies.forEach((k, v) -> sb.append("c:").append(k).append('=').append(v).append('\n'));
        for (ParamSpec param : params) {
            sb.append("p:").append(param.type()).append(':').append(param.name())
                    .append('=').append(param.value()).append('\n');
        }
        return sb.toString();
    }

    /** One-line summary of what this material sets, for result details. */
    public String summary() {
        StringBuilder sb = new StringBuilder();
        if (!headers.isEmpty()) {
            sb.append("headers ").append(headers.keySet());
        }
        if (!cookies.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("cookies ").append(cookies.keySet());
        }
        if (!params.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("params ");
            for (ParamSpec param : params) {
                sb.append(param.type()).append(':').append(param.name()).append(' ');
            }
        }
        return sb.length() == 0 ? "nothing" : sb.toString();
    }

    /** Human-readable summary for the identity panel and result details. */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        headers.forEach((k, v) -> sb.append("header  ").append(k).append(": ")
                .append(Text.abbreviate(v, 120)).append('\n'));
        cookies.forEach((k, v) -> sb.append("cookie  ").append(k).append('=')
                .append(Text.abbreviate(v, 120)).append('\n'));
        for (ParamSpec param : params) {
            sb.append("param   ").append(param.type()).append(' ').append(param.name())
                    .append('=').append(Text.abbreviate(param.value(), 120)).append('\n');
        }
        for (String header : removeHeaders) {
            sb.append("remove  ").append(header).append('\n');
        }
        vars.forEach((k, v) -> sb.append("var     ").append(k).append('=')
                .append(Text.abbreviate(v, 120)).append('\n'));
        if (sb.length() == 0) {
            sb.append("(no auth material -- requests will be sent unmodified)\n");
        }
        return sb.toString();
    }

    /** Mutable builder; also the target of script-result conversion. */
    public static final class Builder {
        private final Map<String, String> headers = new LinkedHashMap<>();
        private final Map<String, String> cookies = new LinkedHashMap<>();
        private final List<ParamSpec> params = new ArrayList<>();
        private final List<String> removeHeaders = new ArrayList<>();
        private final Map<String, String> vars = new LinkedHashMap<>();

        public Builder header(String name, String value) {
            if (!Text.isBlank(name)) {
                headers.put(name.trim(), Text.nullToEmpty(value));
            }
            return this;
        }

        public Builder headers(Map<String, String> values) {
            values.forEach(this::header);
            return this;
        }

        public Builder cookie(String name, String value) {
            if (!Text.isBlank(name)) {
                cookies.put(name.trim(), Text.nullToEmpty(value));
            }
            return this;
        }

        public Builder cookies(Map<String, String> values) {
            values.forEach(this::cookie);
            return this;
        }

        public Builder param(ParamSpec spec) {
            params.add(spec);
            return this;
        }

        public Builder removeHeader(String name) {
            if (!Text.isBlank(name)) {
                removeHeaders.add(name.trim());
            }
            return this;
        }

        public Builder var(String name, String value) {
            if (!Text.isBlank(name)) {
                vars.put(name.trim(), Text.nullToEmpty(value));
            }
            return this;
        }

        public AuthMaterial build() {
            return new AuthMaterial(headers, cookies, params, removeHeaders, vars, System.currentTimeMillis());
        }
    }
}
