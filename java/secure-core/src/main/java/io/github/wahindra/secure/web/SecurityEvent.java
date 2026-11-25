package io.github.wahindra.secure.web;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.logging.LogSanitizer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A security-relevant event for alerting and audit (A09:2025 Security Logging and Alerting
 * Failures): blocked or flagged requests, rate limiting, CORS rejections, access denials and
 * account lockouts. All text fields are sanitized and contain no request payloads, so an event
 * can be sent as-is to a SIEM, Slack or a metrics system. {@link #toJson()} gives one JSON line.
 */
public final class SecurityEvent {

    public enum Type {
        /** A malicious request was rejected (block mode). */
        REQUEST_BLOCKED,
        /** A suspicious or malicious request was let through (monitor mode, or below the threshold). */
        REQUEST_FLAGGED,
        RATE_LIMITED,
        CORS_REJECTED,
        ACCESS_DENIED,
        LOGIN_LOCKED,
        /** A failed login, from {@code LoginAttemptLimiter.onAttempt}. */
        LOGIN_FAILED,
        /** A successful login, from {@code LoginAttemptLimiter.onAttempt}. */
        LOGIN_SUCCEEDED,
        /** Inspection itself failed; the request was rejected unless the filter fails open. */
        INSPECTION_ERROR
    }

    private final Type type;
    private final String incidentId;
    private final Instant timestamp;
    private final String method;
    private final String path;
    private final String remoteAddress;
    private final String principalId;
    private final OwaspCategory category;
    private final List<String> ruleIds;
    private final String detail;

    private SecurityEvent(Builder b) {
        this.type = b.type;
        this.incidentId = b.incidentId;
        this.timestamp = b.timestamp != null ? b.timestamp : Instant.now();
        this.method = clean(b.method, 16);
        this.path = clean(b.path, 300);
        this.remoteAddress = clean(b.remoteAddress, 64);
        this.principalId = clean(b.principalId, 128);
        this.category = b.category;
        this.ruleIds = Collections.unmodifiableList(new ArrayList<String>(b.ruleIds));
        this.detail = clean(b.detail, 1000);
    }

    public static Builder builder(Type type, String incidentId) {
        return new Builder(type, incidentId);
    }

    public Type getType() { return type; }
    public String getIncidentId() { return incidentId; }
    public Instant getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getRemoteAddress() { return remoteAddress; }
    /** The user, when known (for example from {@code ACCESS_DENIED} after authentication). */
    public String getPrincipalId() { return principalId; }
    public OwaspCategory getCategory() { return category; }
    public List<String> getRuleIds() { return ruleIds; }
    public String getDetail() { return detail; }

    /** One JSON object on one line, e.g. for a log shipper or webhook. */
    public String toJson() {
        StringBuilder sb = new StringBuilder("{");
        field(sb, "type", type.name());
        field(sb, "incidentId", incidentId);
        field(sb, "timestamp", timestamp.toString());
        field(sb, "method", method);
        field(sb, "path", path);
        field(sb, "remoteAddress", remoteAddress);
        field(sb, "principalId", principalId);
        if (category != null) {
            field(sb, "owasp", category.id2025());
            field(sb, "category", category.title());
        }
        sb.append(",\"ruleIds\":[");
        for (int i = 0; i < ruleIds.size(); i++) {
            sb.append(i > 0 ? "," : "").append(quote(ruleIds.get(i)));
        }
        sb.append(']');
        field(sb, "detail", detail);
        return sb.append('}').toString();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("security-event type=").append(type).append(" incident=").append(incidentId);
        if (method != null) {
            sb.append(" method=").append(method);
        }
        if (path != null) {
            sb.append(" path=").append(path);
        }
        if (remoteAddress != null) {
            sb.append(" remote=").append(remoteAddress);
        }
        if (principalId != null) {
            sb.append(" principal=").append(principalId);
        }
        if (!ruleIds.isEmpty()) {
            sb.append(" rules=").append(ruleIds);
        }
        if (detail != null) {
            sb.append(" detail=").append(detail);
        }
        return sb.toString();
    }

    private static String clean(String s, int max) {
        return s == null ? null : LogSanitizer.sanitize(s, max);
    }

    private static void field(StringBuilder sb, String name, String value) {
        if (value == null) {
            return;
        }
        if (sb.length() > 1) {
            sb.append(',');
        }
        sb.append(quote(name)).append(':').append(quote(value));
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    public static final class Builder {
        private final Type type;
        private final String incidentId;
        private Instant timestamp;
        private String method;
        private String path;
        private String remoteAddress;
        private String principalId;
        private OwaspCategory category;
        private final List<String> ruleIds = new ArrayList<String>();
        private String detail;

        private Builder(Type type, String incidentId) {
            this.type = type;
            this.incidentId = incidentId;
        }

        public Builder timestamp(Instant v) { timestamp = v; return this; }
        public Builder method(String v) { method = v; return this; }
        public Builder path(String v) { path = v; return this; }
        public Builder remoteAddress(String v) { remoteAddress = v; return this; }
        public Builder principalId(String v) { principalId = v; return this; }
        public Builder category(OwaspCategory v) { category = v; return this; }
        public Builder ruleId(String v) { ruleIds.add(v); return this; }
        public Builder detail(String v) { detail = v; return this; }

        public SecurityEvent build() {
            return new SecurityEvent(this);
        }
    }
}
