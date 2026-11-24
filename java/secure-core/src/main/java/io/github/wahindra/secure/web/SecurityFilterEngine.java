package io.github.wahindra.secure.web;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.detect.Finding;
import io.github.wahindra.secure.errors.SafeErrors;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The request-protection logic shared by every adapter (javax and jakarta servlet filters, the
 * Spring Boot starter). Per request, in this order:
 *
 * <ol>
 *   <li>security headers are added to every response;</li>
 *   <li>CORS preflights are answered directly (204 or 403), and allowed origins get CORS headers;</li>
 *   <li>the rate limit is applied (429 with {@code Retry-After});</li>
 *   <li>path, parameters, selected headers and a JSON body are inspected within a budget; a
 *       malicious request is rejected with 400 in {@link Mode#BLOCK}, only reported in
 *       {@link Mode#MONITOR};</li>
 *   <li>every decision worth knowing about becomes a {@link SecurityEvent} for the listeners.</li>
 * </ol>
 *
 * <p>Adapters read the JSON body themselves (only they can replay it to the application) and
 * pass it to {@link #evaluate(RequestView, String, boolean)}.
 */
public final class SecurityFilterEngine {

    public enum Mode { BLOCK, MONITOR }

    /** Chooses the rate-limit key for a request. Default: the client address. */
    public interface KeyResolver {
        String key(RequestView request);
    }

    /** What the adapter should do with the request. */
    public static final class Verdict {
        private final boolean proceed;
        private final int status;
        private final String body;
        private final Map<String, String> headers;
        private final String incidentId;

        Verdict(boolean proceed, int status, String body, Map<String, String> headers, String incidentId) {
            this.proceed = proceed;
            this.status = status;
            this.body = body;
            this.headers = Collections.unmodifiableMap(headers);
            this.incidentId = incidentId;
        }

        /** {@code true}: pass the request on to the application. */
        public boolean isProceed() { return proceed; }
        /** Response status when not proceeding. */
        public int getStatus() { return status; }
        /** JSON response body when not proceeding, or {@code null} for an empty body. */
        public String getBody() { return body; }
        /** Headers to set on the response in every case. */
        public Map<String, String> getHeaders() { return headers; }
        public String getIncidentId() { return incidentId; }
    }

    public static final int DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

    private static final Logger LOG = Logger.getLogger(SecurityFilterEngine.class.getName());

    private final Mode mode;
    private final HttpRequestInspector inspector;
    private final SecurityHeaders securityHeaders;
    private final CorsPolicy cors;
    private final RateLimiter rateLimiter;
    private final KeyResolver keyResolver;
    private final int maxBodyBytes;
    private final boolean inspectJsonBody;
    private final boolean failOpen;
    private final List<SecurityEventListener> listeners;

    private SecurityFilterEngine(Builder b) {
        this.mode = b.mode;
        this.inspector = b.inspector;
        this.securityHeaders = b.securityHeaders;
        this.cors = b.cors;
        this.rateLimiter = b.rateLimiter;
        this.keyResolver = b.keyResolver;
        this.maxBodyBytes = b.maxBodyBytes;
        this.inspectJsonBody = b.inspectJsonBody;
        this.failOpen = b.failOpen;
        this.listeners = Collections.unmodifiableList(new ArrayList<SecurityEventListener>(b.listeners));
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Defaults: block mode, default inspector and headers, no CORS policy, no rate limit. */
    public static SecurityFilterEngine defaults() {
        return builder().build();
    }

    /**
     * Whether the adapter should read the body before calling {@link #evaluate}: only JSON
     * bodies, and only when body inspection is on. Form bodies arrive through the parameters.
     */
    public boolean wantsBody(RequestView request) {
        if (!inspectJsonBody) {
            return false;
        }
        String m = request.method() == null ? "" : request.method().toUpperCase(Locale.ROOT);
        if ("GET".equals(m) || "HEAD".equals(m) || "OPTIONS".equals(m) || "TRACE".equals(m)) {
            return false;
        }
        String ct = request.contentType();
        if (ct == null) {
            return false;
        }
        String t = ct.toLowerCase(Locale.ROOT);
        return t.startsWith("application/json") || t.contains("+json");
    }

    /** Bytes the adapter should read at most; reading one byte more tells it the body is too large. */
    public int getMaxBodyBytes() {
        return maxBodyBytes;
    }

    /**
     * @param request      the request
     * @param jsonBody     the JSON body as text if {@link #wantsBody} was true, else {@code null}
     * @param bodyTooLarge the JSON body exceeded {@link #getMaxBodyBytes()}; it is then not inspected
     *                     and the request counts as malicious (fail closed)
     */
    public Verdict evaluate(RequestView request, String jsonBody, boolean bodyTooLarge) {
        Map<String, String> headers = new LinkedHashMap<String, String>();
        if (securityHeaders != null) {
            headers.putAll(securityHeaders.asMap());
        }

        if (cors != null) {
            CorsPolicy.Result c = cors.evaluate(request.header("Origin"), request.method(),
                    request.header("Access-Control-Request-Method"), request.header("Access-Control-Request-Headers"));
            headers.putAll(c.getHeaders());
            if (c.isPreflight()) {
                if (c.isAllowed()) {
                    return new Verdict(false, 204, null, headers, null);
                }
                String id = SafeErrors.newIncidentId();
                emit(event(SecurityEvent.Type.CORS_REJECTED, id, request).category(OwaspCategory.SECURITY_MISCONFIGURATION)
                        .detail("origin not allowed: " + request.header("Origin")).build());
                return new Verdict(false, 403, error("cors_rejected", id), headers, id);
            }
            // Simple cross-origin requests from unlisted origins get no CORS headers, so the browser
            // will not let the page read the response. They are not rejected, because browsers also
            // send Origin on same-origin POSTs.
        }

        if (rateLimiter != null) {
            RateLimiter.Decision d = rateLimiter.tryAcquire(keyResolver.key(request));
            headers.putAll(d.headers());
            if (!d.isAllowed()) {
                String id = SafeErrors.newIncidentId();
                emit(event(SecurityEvent.Type.RATE_LIMITED, id, request).category(OwaspCategory.INSECURE_DESIGN)
                        .detail("limit " + d.getLimit() + ", retry after " + d.retryAfterSeconds() + " s").build());
                return new Verdict(false, 429, error("rate_limited", id), headers, id);
            }
        }

        HttpRequestInspector.Report report;
        try {
            report = inspector.inspect(request.rawPath(), request.parameters(), request.headers(), bodyTooLarge ? null : jsonBody);
        } catch (RuntimeException e) {
            String id = SafeErrors.log(LOG, e, "request inspection failed");
            emit(event(SecurityEvent.Type.INSPECTION_ERROR, id, request).detail(e.getClass().getSimpleName()).build());
            return failOpen ? new Verdict(true, 0, null, headers, id)
                    : new Verdict(false, 400, error("request_rejected", id), headers, id);
        }

        boolean malicious = bodyTooLarge || report.isMalicious();
        if (bodyTooLarge || report.isSuspicious()) {
            String id = SafeErrors.newIncidentId();
            boolean block = mode == Mode.BLOCK && malicious;
            SecurityEvent.Builder ev = event(block ? SecurityEvent.Type.REQUEST_BLOCKED : SecurityEvent.Type.REQUEST_FLAGGED, id, request)
                    .detail((bodyTooLarge ? "json-body-too-large" + (report.isSuspicious() ? ", " : "") : "") + report.summary());
            OwaspCategory category = null;
            for (Finding f : report.getFindings()) {
                ev.ruleId(f.getRuleId());
                if (category == null) {
                    category = f.getCategory();
                }
            }
            ev.category(category != null ? category : OwaspCategory.INSECURE_DESIGN);
            emit(ev.build());
            if (block) {
                return new Verdict(false, 400, error("request_rejected", id), headers, id);
            }
        }
        return new Verdict(true, 0, null, headers, null);
    }

    /** Sends an event to the log and every listener. Use for events from application code too. */
    public void emit(SecurityEvent event) {
        Level level = event.getType() == SecurityEvent.Type.REQUEST_FLAGGED ? Level.INFO : Level.WARNING;
        LOG.log(level, event.toString());
        for (SecurityEventListener l : listeners) {
            try {
                l.onEvent(event);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "security event listener failed: " + e.getClass().getName());
            }
        }
    }

    public Mode getMode() {
        return mode;
    }

    private static SecurityEvent.Builder event(SecurityEvent.Type type, String id, RequestView r) {
        return SecurityEvent.builder(type, id).method(r.method()).path(r.rawPath()).remoteAddress(r.remoteAddress());
    }

    private static String error(String code, String incidentId) {
        return "{\"error\":\"" + code + "\",\"incidentId\":\"" + incidentId + "\"}";
    }

    public static final class Builder {
        private Mode mode = Mode.BLOCK;
        private HttpRequestInspector inspector = new HttpRequestInspector();
        private SecurityHeaders securityHeaders = SecurityHeaders.defaults();
        private CorsPolicy cors;
        private RateLimiter rateLimiter;
        private KeyResolver keyResolver = new KeyResolver() {
            @Override
            public String key(RequestView request) {
                return request.remoteAddress();
            }
        };
        private int maxBodyBytes = DEFAULT_MAX_BODY_BYTES;
        private boolean inspectJsonBody = true;
        private boolean failOpen;
        private final List<SecurityEventListener> listeners = new ArrayList<SecurityEventListener>();

        private Builder() {
        }

        public Builder mode(Mode v) { mode = v; return this; }
        public Builder inspector(HttpRequestInspector v) { inspector = v; return this; }
        /** {@code null} to leave response headers alone. */
        public Builder securityHeaders(SecurityHeaders v) { securityHeaders = v; return this; }
        /** {@code null} (default) for no CORS handling. */
        public Builder cors(CorsPolicy v) { cors = v; return this; }
        /** {@code null} (default) for no rate limit. */
        public Builder rateLimiter(RateLimiter v) { rateLimiter = v; return this; }
        public Builder rateLimitKey(KeyResolver v) { keyResolver = v; return this; }

        public Builder maxBodyBytes(int v) {
            if (v < 1) {
                throw new IllegalArgumentException("maxBodyBytes must be positive");
            }
            maxBodyBytes = v;
            return this;
        }

        public Builder inspectJsonBody(boolean v) { inspectJsonBody = v; return this; }
        /** Let requests through when inspection itself throws. Default {@code false} (reject). */
        public Builder failOpen(boolean v) { failOpen = v; return this; }
        public Builder listener(SecurityEventListener v) { listeners.add(v); return this; }

        public SecurityFilterEngine build() {
            return new SecurityFilterEngine(this);
        }
    }
}
