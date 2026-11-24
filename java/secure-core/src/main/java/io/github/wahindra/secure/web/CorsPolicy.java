package io.github.wahindra.secure.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Strict CORS: only origins you list may call the API from a browser. Never reflects an arbitrary
 * {@code Origin}, never allows the {@code null} origin, and refuses the {@code *} plus credentials
 * combination that browsers reject and that would expose logged-in users.
 *
 * <pre>
 * CorsPolicy cors = CorsPolicy.builder()
 *     .allowOrigins("https://app.example.com", "https://*.admin.example.com")
 *     .allowCredentials(true)
 *     .build();
 * </pre>
 */
public final class CorsPolicy {

    /** Result of evaluating one request. */
    public static final class Result {
        private final boolean preflight;
        private final boolean allowed;
        private final Map<String, String> headers;

        Result(boolean preflight, boolean allowed, Map<String, String> headers) {
            this.preflight = preflight;
            this.allowed = allowed;
            this.headers = Collections.unmodifiableMap(headers);
        }

        /** An {@code OPTIONS} preflight: answer it directly (204 if allowed, 403 if not), don't route it. */
        public boolean isPreflight() { return preflight; }
        /** {@code false} when a browser origin is not on the list. */
        public boolean isAllowed() { return allowed; }
        /** Headers to add to the response (always includes {@code Vary: Origin} for cross-origin requests). */
        public Map<String, String> getHeaders() { return headers; }
    }

    private final List<String> exactOrigins;
    private final List<String> wildcardSuffixes;
    private final boolean anyOrigin;
    private final Set<String> methods;
    private final Set<String> allowHeaders;
    private final List<String> exposeHeaders;
    private final boolean credentials;
    private final long maxAgeSeconds;

    private CorsPolicy(Builder b) {
        List<String> exact = new ArrayList<String>();
        List<String> wild = new ArrayList<String>();
        boolean any = false;
        for (String o : b.origins) {
            String n = o.trim().toLowerCase(Locale.ROOT);
            if ("*".equals(n)) {
                any = true;
            } else if (n.contains("://*.")) {
                wild.add(n.replace("://*.", "://"));
            } else {
                exact.add(stripTrailingSlash(n));
            }
        }
        if (any && b.credentials) {
            throw new IllegalArgumentException("allowOrigins(\"*\") cannot be combined with allowCredentials(true)");
        }
        this.exactOrigins = exact;
        this.wildcardSuffixes = wild;
        this.anyOrigin = any;
        this.methods = upper(b.methods);
        this.allowHeaders = lower(b.allowHeaders);
        this.exposeHeaders = new ArrayList<String>(b.exposeHeaders);
        this.credentials = b.credentials;
        this.maxAgeSeconds = b.maxAgeSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * @param origin                     the request's {@code Origin} header, or {@code null}
     * @param method                     the request method
     * @param requestMethod              {@code Access-Control-Request-Method}, for preflights
     * @param requestHeaders             {@code Access-Control-Request-Headers}, for preflights
     */
    public Result evaluate(String origin, String method, String requestMethod, String requestHeaders) {
        Map<String, String> h = new LinkedHashMap<String, String>();
        boolean preflight = "OPTIONS".equalsIgnoreCase(method) && requestMethod != null;
        if (origin == null) {
            // Same-origin or non-browser request: CORS does not apply.
            return new Result(false, true, h);
        }
        h.put("Vary", preflight ? "Origin, Access-Control-Request-Method, Access-Control-Request-Headers" : "Origin");
        if (!isAllowedOrigin(origin)) {
            return new Result(preflight, false, h);
        }
        h.put("Access-Control-Allow-Origin", anyOrigin && !credentials ? "*" : origin);
        if (credentials) {
            h.put("Access-Control-Allow-Credentials", "true");
        }
        if (preflight) {
            if (!methods.contains(requestMethod.trim().toUpperCase(Locale.ROOT))) {
                return new Result(true, false, onlyVary(h));
            }
            if (requestHeaders != null && !requestHeaders.trim().isEmpty()) {
                for (String rh : requestHeaders.split(",")) {
                    if (!rh.trim().isEmpty() && !allowHeaders.contains(rh.trim().toLowerCase(Locale.ROOT))) {
                        return new Result(true, false, onlyVary(h));
                    }
                }
            }
            h.put("Access-Control-Allow-Methods", join(methods));
            if (!allowHeaders.isEmpty()) {
                h.put("Access-Control-Allow-Headers", join(allowHeaders));
            }
            h.put("Access-Control-Max-Age", String.valueOf(maxAgeSeconds));
        } else if (!exposeHeaders.isEmpty()) {
            h.put("Access-Control-Expose-Headers", join(exposeHeaders));
        }
        return new Result(preflight, true, h);
    }

    public boolean isAllowedOrigin(String origin) {
        if (origin == null) {
            return false;
        }
        String o = stripTrailingSlash(origin.trim().toLowerCase(Locale.ROOT));
        // "null" comes from sandboxed iframes, file:// pages and redirects: never trust it.
        if ("null".equals(o) || !(o.startsWith("https://") || o.startsWith("http://"))) {
            return false;
        }
        String afterScheme = o.substring(o.indexOf("://") + 3);
        if (afterScheme.isEmpty() || afterScheme.contains("/") || afterScheme.contains("@")) {
            return false;
        }
        if (anyOrigin || exactOrigins.contains(o)) {
            return true;
        }
        for (String w : wildcardSuffixes) {
            // w is e.g. "https://admin.example.com" for "https://*.admin.example.com".
            String scheme = w.substring(0, w.indexOf("://") + 3);
            String domain = w.substring(scheme.length());
            if (o.startsWith(scheme) && afterScheme.endsWith("." + domain) && afterScheme.length() > domain.length() + 1) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, String> onlyVary(Map<String, String> h) {
        Map<String, String> v = new LinkedHashMap<String, String>();
        v.put("Vary", h.get("Vary"));
        return v;
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static Set<String> upper(List<String> in) {
        Set<String> s = new LinkedHashSet<String>();
        for (String v : in) {
            s.add(v.trim().toUpperCase(Locale.ROOT));
        }
        return s;
    }

    private static Set<String> lower(List<String> in) {
        Set<String> s = new LinkedHashSet<String>();
        for (String v : in) {
            s.add(v.trim().toLowerCase(Locale.ROOT));
        }
        return s;
    }

    private static String join(Iterable<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String v : values) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(v);
        }
        return sb.toString();
    }

    public static final class Builder {
        private List<String> origins = new ArrayList<String>();
        private List<String> methods = new ArrayList<String>(Arrays.asList("GET", "HEAD", "POST"));
        private List<String> allowHeaders = new ArrayList<String>(Arrays.asList("Content-Type", "Authorization"));
        private List<String> exposeHeaders = new ArrayList<String>();
        private boolean credentials;
        private long maxAgeSeconds = 600;

        private Builder() {
        }

        /** Exact origins ({@code https://app.example.com}) or subdomain wildcards ({@code https://*.example.com}). */
        public Builder allowOrigins(String... values) {
            origins = new ArrayList<String>(Arrays.asList(values));
            return this;
        }

        public Builder allowMethods(String... values) {
            methods = new ArrayList<String>(Arrays.asList(values));
            return this;
        }

        public Builder allowHeaders(String... values) {
            allowHeaders = new ArrayList<String>(Arrays.asList(values));
            return this;
        }

        public Builder exposeHeaders(String... values) {
            exposeHeaders = new ArrayList<String>(Arrays.asList(values));
            return this;
        }

        /** Cookies / Authorization on cross-origin calls. Not allowed together with origin {@code *}. */
        public Builder allowCredentials(boolean value) {
            credentials = value;
            return this;
        }

        public Builder maxAgeSeconds(long value) {
            maxAgeSeconds = value;
            return this;
        }

        public CorsPolicy build() {
            if (origins.isEmpty()) {
                throw new IllegalArgumentException("list at least one allowed origin");
            }
            return new CorsPolicy(this);
        }
    }
}
