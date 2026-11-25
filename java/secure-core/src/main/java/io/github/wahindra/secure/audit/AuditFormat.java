package io.github.wahindra.secure.audit;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.regex.Pattern;

/**
 * How an {@link AuditRecord} is written: one line per record. The JavaScript library produces
 * byte-identical lines for the same record (checked by the shared test vectors).
 *
 * <ul>
 *   <li>{@link #JSON}: flat JSON, the library's own field names. Good for files and log shippers.</li>
 *   <li>{@link #ECS}: Elastic Common Schema 8.x (Elastic, OpenSearch, Wazuh, Sentinel's ECS parser).</li>
 *   <li>{@link #CEF}: ArcSight Common Event Format (ArcSight, QRadar, Microsoft Sentinel, Splunk).</li>
 * </ul>
 */
public enum AuditFormat {

    JSON {
        @Override
        public String format(AuditRecord r) {
            Json j = new Json();
            j.str("timestamp", timestamp(r));
            j.str("kind", r.getKind().name().toLowerCase(java.util.Locale.ROOT));
            j.str("event", r.getEvent());
            j.str("outcome", r.getOutcome().id());
            j.num("severity", r.getSeverity());
            j.str("incidentId", r.getIncidentId());
            j.str("principalId", r.getPrincipalId());
            j.str("remoteAddress", r.getRemoteAddress());
            j.str("method", r.getMethod());
            j.str("path", r.getPath());
            j.str("resource", r.getResource());
            j.str("owasp", r.getOwasp());
            j.str("category", r.getCategory());
            j.arr("ruleIds", r.getRuleIds());
            j.str("detail", r.getDetail());
            return j.end();
        }
    },

    ECS {
        @Override
        public String format(AuditRecord r) {
            Json j = new Json();
            j.str("@timestamp", timestamp(r));
            j.open("ecs").str("version", "8.11.0").close();
            j.open("event");
            AuditRecord.Outcome o = r.getOutcome();
            j.str("kind", o == AuditRecord.Outcome.BLOCKED || o == AuditRecord.Outcome.FLAGGED ? "alert" : "event");
            String[] category = ecsCategory(r);
            if (category != null) {
                j.arr("category", java.util.Arrays.asList(category));
            }
            j.arr("type", java.util.Collections.singletonList(ecsType(o)));
            j.str("action", r.getEvent());
            j.str("outcome", ecsOutcome(o));
            j.num("severity", r.getSeverity());
            j.str("id", r.getIncidentId());
            j.close();
            if (r.getPrincipalId() != null) {
                j.open("user").str("id", r.getPrincipalId()).close();
            }
            if (r.getRemoteAddress() != null) {
                j.open("source").str(isIp(r.getRemoteAddress()) ? "ip" : "address", r.getRemoteAddress()).close();
            }
            if (r.getMethod() != null) {
                j.open("http").open("request").str("method", r.getMethod()).close().close();
            }
            if (r.getPath() != null) {
                j.open("url").str("path", r.getPath()).close();
            }
            if (!r.getRuleIds().isEmpty()) {
                j.open("rule").arr("id", r.getRuleIds()).close();
            }
            j.open("labels");
            j.str("audit_kind", r.getKind().name().toLowerCase(java.util.Locale.ROOT));
            j.str("audit_outcome", o.id());
            j.str("resource", r.getResource());
            j.str("owasp", r.getOwasp());
            j.str("owasp_category", r.getCategory());
            j.close();
            j.str("message", r.getDetail());
            return j.end();
        }
    },

    CEF {
        @Override
        public String format(AuditRecord r) {
            StringBuilder sb = new StringBuilder("CEF:0|wahindra|secure|1|");
            sb.append(cefHeader(r.getEvent())).append('|').append(cefHeader(cefName(r))).append('|').append(r.getSeverity()).append('|');
            StringBuilder ext = new StringBuilder();
            ext(ext, "rt", String.valueOf(r.getTimestamp().toEpochMilli()));
            ext(ext, "outcome", r.getOutcome().id());
            ext(ext, "externalId", r.getIncidentId());
            ext(ext, "suser", r.getPrincipalId());
            if (r.getRemoteAddress() != null) {
                ext(ext, isIp(r.getRemoteAddress()) ? "src" : "shost", r.getRemoteAddress());
            }
            ext(ext, "requestMethod", r.getMethod());
            ext(ext, "request", r.getPath());
            if (r.getOwasp() != null) {
                ext(ext, "cs1Label", "owasp");
                ext(ext, "cs1", r.getOwasp());
            }
            if (!r.getRuleIds().isEmpty()) {
                ext(ext, "cs2Label", "rules");
                ext(ext, "cs2", join(r.getRuleIds()));
            }
            if (r.getResource() != null) {
                ext(ext, "cs3Label", "resource");
                ext(ext, "cs3", r.getResource());
            }
            ext(ext, "cs4Label", "kind");
            ext(ext, "cs4", r.getKind().name().toLowerCase(java.util.Locale.ROOT));
            ext(ext, "msg", r.getDetail());
            return sb.append(ext).toString();
        }
    };

    /** One line, without a line terminator. */
    public abstract String format(AuditRecord record);

    /** {@code json}, {@code ecs} or {@code cef}, any case. */
    public static AuditFormat parse(String name) {
        return valueOf(name.trim().toUpperCase(java.util.Locale.ROOT));
    }

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final Pattern IP = Pattern.compile("^(?:\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$");

    /** ISO 8601, UTC, always milliseconds (the same as JavaScript's {@code toISOString()}). */
    static String timestamp(AuditRecord r) {
        return TS.format(r.getTimestamp().truncatedTo(ChronoUnit.MILLIS));
    }

    static boolean isIp(String s) {
        return IP.matcher(s).matches();
    }

    static String[] ecsCategory(AuditRecord r) {
        if (r.getKind() != AuditRecord.Kind.SECURITY) {
            return null;
        }
        String e = r.getEvent();
        if (e.startsWith("LOGIN_")) {
            return new String[] {"authentication"};
        }
        if ("REQUEST_BLOCKED".equals(e) || "REQUEST_FLAGGED".equals(e)) {
            return new String[] {"intrusion_detection", "web"};
        }
        return new String[] {"web"};
    }

    static String ecsType(AuditRecord.Outcome o) {
        switch (o) {
            case BLOCKED:
            case DENIED:
                return "denied";
            case SUCCESS:
                return "allowed";
            case ERROR:
                return "error";
            default:
                return "info";
        }
    }

    static String ecsOutcome(AuditRecord.Outcome o) {
        switch (o) {
            case SUCCESS:
                return "success";
            case FAILURE:
            case DENIED:
            case BLOCKED:
                return "failure";
            default:
                return "unknown";
        }
    }

    static String cefName(AuditRecord r) {
        if (r.getKind() == AuditRecord.Kind.SECURITY) {
            String e = r.getEvent();
            if ("REQUEST_BLOCKED".equals(e)) return "Malicious request blocked";
            if ("REQUEST_FLAGGED".equals(e)) return "Suspicious request flagged";
            if ("RATE_LIMITED".equals(e)) return "Rate limit exceeded";
            if ("CORS_REJECTED".equals(e)) return "CORS request rejected";
            if ("ACCESS_DENIED".equals(e)) return "Access denied";
            if ("LOGIN_LOCKED".equals(e)) return "Account locked out";
            if ("LOGIN_FAILED".equals(e)) return "Login failed";
            if ("LOGIN_SUCCEEDED".equals(e)) return "Login succeeded";
            if ("INSPECTION_ERROR".equals(e)) return "Request inspection failed";
        }
        return r.getEvent();
    }

    private static String cefHeader(String s) {
        return s.replace("\\", "\\\\").replace("|", "\\|");
    }

    private static void ext(StringBuilder sb, String key, String value) {
        if (value == null) {
            return;
        }
        if (sb.length() > 0) {
            sb.append(' ');
        }
        sb.append(key).append('=').append(value.replace("\\", "\\\\").replace("=", "\\=")
                .replace("\r", "\\r").replace("\n", "\\n"));
    }

    private static String join(List<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String v : values) {
            sb.append(sb.length() > 0 ? "," : "").append(v);
        }
        return sb.toString();
    }

    /** Minimal JSON writer: fixed field order, nulls and empty objects left out. */
    static final class Json {
        private final StringBuilder sb = new StringBuilder("{");
        /** Per nesting level: where the object started, and whether it has a field yet. */
        private final java.util.ArrayDeque<int[]> stack = new java.util.ArrayDeque<int[]>();
        private boolean hasField;

        Json str(String name, String value) {
            if (value != null) {
                name(name).append(quote(value));
            }
            return this;
        }

        Json num(String name, long value) {
            name(name).append(value);
            return this;
        }

        Json arr(String name, List<String> values) {
            if (values == null || values.isEmpty()) {
                return this;
            }
            StringBuilder a = name(name).append('[');
            for (int i = 0; i < values.size(); i++) {
                a.append(i > 0 ? "," : "").append(quote(values.get(i)));
            }
            a.append(']');
            return this;
        }

        Json open(String name) {
            stack.push(new int[] {sb.length(), hasField ? 1 : 0});
            name(name).append('{');
            hasField = false;
            return this;
        }

        Json close() {
            int[] frame = stack.pop();
            if (!hasField) {
                sb.setLength(frame[0]); // drop an empty object, and its comma
                hasField = frame[1] == 1;
            } else {
                sb.append('}');
                hasField = true;
            }
            return this;
        }

        String end() {
            return sb.append('}').toString();
        }

        private StringBuilder name(String name) {
            if (hasField) {
                sb.append(',');
            }
            hasField = true;
            return sb.append(quote(name)).append(':');
        }

        static String quote(String s) {
            StringBuilder q = new StringBuilder(s.length() + 2).append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"' || c == '\\') {
                    q.append('\\').append(c);
                } else if (c < 0x20 || Character.isSurrogate(c) && !validSurrogate(s, i)) {
                    q.append(String.format("\\u%04x", (int) c));
                } else {
                    q.append(c);
                }
            }
            return q.append('"').toString();
        }

        private static boolean validSurrogate(String s, int i) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                return i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
            }
            return i > 0 && Character.isHighSurrogate(s.charAt(i - 1));
        }
    }
}
