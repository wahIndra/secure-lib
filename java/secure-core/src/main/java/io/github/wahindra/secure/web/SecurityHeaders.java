package io.github.wahindra.secure.web;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Recommended HTTP response headers (Security Misconfiguration). Defaults suit an API or a
 * server-rendered app without inline scripts; loosen the CSP per app rather than globally.
 */
public final class SecurityHeaders {

    public static final String DEFAULT_CSP =
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
                    + "frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests";

    private final Map<String, String> headers;

    private SecurityHeaders(Map<String, String> headers) {
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<String, String>(headers));
    }

    public static SecurityHeaders defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public Map<String, String> asMap() {
        return headers;
    }

    /** Headers that reveal server software; remove them from responses where the container allows. */
    public static String[] leakyHeaders() {
        return new String[] {"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"};
    }

    public static final class Builder {
        private final Map<String, String> h = new LinkedHashMap<String, String>();

        private Builder() {
            h.put("Content-Security-Policy", DEFAULT_CSP);
            h.put("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            h.put("X-Content-Type-Options", "nosniff");
            h.put("X-Frame-Options", "DENY");
            h.put("Referrer-Policy", "strict-origin-when-cross-origin");
            h.put("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
            h.put("Cross-Origin-Opener-Policy", "same-origin");
            h.put("Cross-Origin-Resource-Policy", "same-origin");
            h.put("X-Permitted-Cross-Domain-Policies", "none");
        }

        public Builder contentSecurityPolicy(String value) {
            return set("Content-Security-Policy", value);
        }

        /** Marks responses as private and non-cacheable; use for authenticated pages and APIs. */
        public Builder noStore() {
            h.put("Cache-Control", "no-store");
            h.put("Pragma", "no-cache");
            return this;
        }

        public Builder hstsPreload() {
            return set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
        }

        /** Set a header, or remove it by passing {@code null}. */
        public Builder set(String name, String value) {
            if (value == null) {
                h.remove(name);
            } else {
                h.put(name, value);
            }
            return this;
        }

        public SecurityHeaders build() {
            return new SecurityHeaders(h);
        }
    }
}
