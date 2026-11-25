package io.github.wahindra.secure.audit;

import io.github.wahindra.secure.logging.LogSanitizer;
import io.github.wahindra.secure.web.SecurityEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * One audit log record: either a {@link SecurityEvent} from the library (a blocked request, a
 * failed login...) or an action of the application itself ({@code order.refund}, {@code
 * user.role.change}). All text is sanitized (no line breaks, secrets masked, length capped), so a
 * record can be written to a file or a SIEM as it is.
 *
 * <pre>
 * audit.record(AuditRecord.builder("order.refund").principalId(user.getId())
 *         .resource("order/" + id).outcome(AuditRecord.Outcome.SUCCESS).detail("amount=12.50").build());
 * </pre>
 */
public final class AuditRecord {

    /** Where a record comes from. */
    public enum Kind {
        /** Reported by the library: attacks, denials, rate limits, logins. */
        SECURITY,
        /** Recorded by the application with {@link AuditLog#record(AuditRecord)}. */
        APPLICATION
    }

    /** What happened. Maps to ECS {@code event.outcome} and to the CEF / syslog severity. */
    public enum Outcome {
        SUCCESS, FAILURE, DENIED, BLOCKED, FLAGGED, ERROR;

        String id() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    private final Instant timestamp;
    private final Kind kind;
    private final String event;
    private final Outcome outcome;
    private final int severity;
    private final String incidentId;
    private final String principalId;
    private final String remoteAddress;
    private final String method;
    private final String path;
    private final String resource;
    private final String owasp;
    private final String category;
    private final List<String> ruleIds;
    private final String detail;

    private AuditRecord(Builder b) {
        this.timestamp = b.timestamp != null ? b.timestamp : Instant.now();
        this.kind = b.kind;
        this.event = clean(b.event, 100);
        this.outcome = b.outcome;
        this.severity = b.severity >= 0 ? Math.min(10, b.severity) : defaultSeverity(b.event, b.kind, b.outcome);
        this.incidentId = clean(b.incidentId, 64);
        this.principalId = clean(b.principalId, 128);
        this.remoteAddress = clean(b.remoteAddress, 64);
        this.method = clean(b.method, 16);
        this.path = clean(b.path, 300);
        this.resource = clean(b.resource, 300);
        this.owasp = clean(b.owasp, 16);
        this.category = clean(b.category, 100);
        List<String> rules = new ArrayList<String>();
        for (String r : b.ruleIds) {
            rules.add(clean(r, 100));
        }
        this.ruleIds = Collections.unmodifiableList(rules);
        this.detail = clean(b.detail, 1000);
    }

    /** An application action, e.g. {@code builder("order.refund")}. Outcome defaults to SUCCESS. */
    public static Builder builder(String event) {
        if (event == null || event.trim().isEmpty()) {
            throw new IllegalArgumentException("event name is required, e.g. \"order.refund\"");
        }
        return new Builder(Kind.APPLICATION, event.trim());
    }

    /** The audit record for a library security event. */
    public static AuditRecord of(SecurityEvent e) {
        Builder b = new Builder(Kind.SECURITY, e.getType().name())
                .timestamp(e.getTimestamp())
                .outcome(outcomeOf(e.getType()))
                .incidentId(e.getIncidentId())
                .principalId(e.getPrincipalId())
                .remoteAddress(e.getRemoteAddress())
                .method(e.getMethod())
                .path(e.getPath())
                .detail(e.getDetail());
        if (e.getCategory() != null) {
            b.owasp(e.getCategory().id2025()).category(e.getCategory().title());
        }
        for (String r : e.getRuleIds()) {
            b.ruleId(r);
        }
        return b.build();
    }

    static Outcome outcomeOf(SecurityEvent.Type t) {
        switch (t) {
            case REQUEST_BLOCKED:
                return Outcome.BLOCKED;
            case REQUEST_FLAGGED:
                return Outcome.FLAGGED;
            case LOGIN_FAILED:
                return Outcome.FAILURE;
            case LOGIN_SUCCEEDED:
                return Outcome.SUCCESS;
            case INSPECTION_ERROR:
                return Outcome.ERROR;
            default:
                return Outcome.DENIED;
        }
    }

    /** 0 to 10, as in CEF. Security events have fixed values; application events follow the outcome. */
    static int defaultSeverity(String event, Kind kind, Outcome outcome) {
        if (kind == Kind.SECURITY) {
            if ("REQUEST_BLOCKED".equals(event) || "LOGIN_LOCKED".equals(event)) {
                return 7;
            }
            if ("INSPECTION_ERROR".equals(event)) {
                return 6;
            }
            if ("REQUEST_FLAGGED".equals(event) || "ACCESS_DENIED".equals(event)) {
                return 5;
            }
            if ("RATE_LIMITED".equals(event) || "CORS_REJECTED".equals(event)) {
                return 4;
            }
        }
        switch (outcome) {
            case BLOCKED:
                return 7;
            case ERROR:
                return 6;
            case DENIED:
            case FLAGGED:
                return 5;
            case FAILURE:
                return 3;
            default:
                return 1;
        }
    }

    public Instant getTimestamp() { return timestamp; }
    public Kind getKind() { return kind; }
    /** {@code REQUEST_BLOCKED}, {@code LOGIN_FAILED}... or the application's own name. */
    public String getEvent() { return event; }
    public Outcome getOutcome() { return outcome; }
    /** 0 (informational) to 10 (critical). */
    public int getSeverity() { return severity; }
    public String getIncidentId() { return incidentId; }
    public String getPrincipalId() { return principalId; }
    public String getRemoteAddress() { return remoteAddress; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    /** The object acted on, e.g. {@code order/42}. */
    public String getResource() { return resource; }
    /** OWASP Top 10 2025 id, e.g. {@code A05}. */
    public String getOwasp() { return owasp; }
    public String getCategory() { return category; }
    public List<String> getRuleIds() { return ruleIds; }
    public String getDetail() { return detail; }

    private static String clean(String s, int max) {
        return s == null ? null : LogSanitizer.sanitize(s, max);
    }

    public static final class Builder {
        private final Kind kind;
        private final String event;
        private Instant timestamp;
        private Outcome outcome = Outcome.SUCCESS;
        private int severity = -1;
        private String incidentId;
        private String principalId;
        private String remoteAddress;
        private String method;
        private String path;
        private String resource;
        private String owasp;
        private String category;
        private final List<String> ruleIds = new ArrayList<String>();
        private String detail;

        private Builder(Kind kind, String event) {
            this.kind = kind;
            this.event = event;
            this.incidentId = UUID.randomUUID().toString();
        }

        public Builder timestamp(Instant v) { timestamp = v; return this; }
        public Builder outcome(Outcome v) {
            if (v == null) {
                throw new IllegalArgumentException("outcome");
            }
            outcome = v;
            return this;
        }
        /** Override the severity (0 to 10). */
        public Builder severity(int v) {
            if (v < 0 || v > 10) {
                throw new IllegalArgumentException("severity must be 0..10");
            }
            severity = v;
            return this;
        }
        /** Defaults to a random UUID; set it to correlate with an error response's incident id. */
        public Builder incidentId(String v) { incidentId = v; return this; }
        public Builder principalId(String v) { principalId = v; return this; }
        public Builder remoteAddress(String v) { remoteAddress = v; return this; }
        public Builder method(String v) { method = v; return this; }
        public Builder path(String v) { path = v; return this; }
        public Builder resource(String v) { resource = v; return this; }
        public Builder owasp(String v) { owasp = v; return this; }
        public Builder category(String v) { category = v; return this; }
        public Builder ruleId(String v) {
            if (v != null) {
                ruleIds.add(v);
            }
            return this;
        }
        /** Free text. Never put passwords, tokens or full request bodies here (secrets are masked anyway). */
        public Builder detail(String v) { detail = v; return this; }

        public AuditRecord build() {
            return new AuditRecord(this);
        }
    }
}
