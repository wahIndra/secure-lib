package io.github.wahindra.secure.web;

import io.github.wahindra.secure.InputInspector;
import io.github.wahindra.secure.detect.DetectionResult;
import io.github.wahindra.secure.detect.Finding;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Framework-neutral request inspection used by the servlet filters (and usable from Spring
 * interceptors, JAX-RS filters, Vert.x handlers...). Inspects the path, every parameter name and
 * value, a configurable set of headers, and the keys and string values of a JSON body.
 *
 * <p><b>Budget.</b> Inspection stops, and the request counts as malicious, once it exceeds
 * {@code maxValues} values, {@code maxInspectedChars} characters in total, or {@code maxJsonDepth}
 * levels of JSON nesting. Skipping the rest instead would let a payload hide behind padding, and
 * an unbounded inspection would let one request use seconds of CPU.
 */
public final class HttpRequestInspector {

    public static final List<String> DEFAULT_HEADERS = Collections.unmodifiableList(Arrays.asList(
            "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Original-URL",
            "X-Rewrite-URL", "Origin"));

    public static final int DEFAULT_MAX_VALUES = 2000;
    public static final int DEFAULT_MAX_INSPECTED_CHARS = 256 * 1024;
    public static final int DEFAULT_MAX_JSON_DEPTH = 20;

    private final InputInspector inspector;
    private final Set<String> headers;
    private final int maxValues;
    private final int maxInspectedChars;
    private final int maxJsonDepth;

    public HttpRequestInspector() {
        this(builder());
    }

    public HttpRequestInspector(InputInspector inspector, List<String> headersToInspect) {
        this(builder().inspector(inspector).headers(headersToInspect));
    }

    private HttpRequestInspector(Builder b) {
        this.inspector = b.inspector;
        Set<String> h = new LinkedHashSet<String>();
        for (String name : b.headers) {
            h.add(name.toLowerCase(Locale.ROOT));
        }
        this.headers = Collections.unmodifiableSet(h);
        this.maxValues = b.maxValues;
        this.maxInspectedChars = b.maxInspectedChars;
        this.maxJsonDepth = b.maxJsonDepth;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * @param rawPath      the raw (undecoded) request URI, e.g. {@code getRequestURI()}
     * @param parameters   query and form parameters
     * @param headerValues header name to value; names are matched case-insensitively
     */
    public Report inspect(String rawPath, Map<String, String[]> parameters, Map<String, String> headerValues) {
        return inspect(rawPath, parameters, headerValues, null);
    }

    /**
     * @param jsonBody the request body if it is JSON, or {@code null}. Invalid JSON is inspected as
     *                 plain text, so a malformed body cannot bypass inspection.
     */
    public Report inspect(String rawPath, Map<String, String[]> parameters, Map<String, String> headerValues, String jsonBody) {
        final Report report = new Report();
        // Request paths are always absolute; drop the leading slash so PATH_ABSOLUTE does not fire on every request.
        if (!check(report, "path", rawPath == null ? null : rawPath.replaceFirst("^/+", ""))) {
            return report;
        }
        if (parameters != null) {
            for (Map.Entry<String, String[]> e : parameters.entrySet()) {
                String name = e.getKey();
                if (!check(report, "param-name", name)) {
                    return report;
                }
                if (e.getValue() != null) {
                    for (String v : e.getValue()) {
                        if (!check(report, "param:" + safeName(name), v)) {
                            return report;
                        }
                    }
                }
            }
        }
        if (headerValues != null) {
            for (Map.Entry<String, String> e : headerValues.entrySet()) {
                if (e.getKey() != null && headers.contains(e.getKey().toLowerCase(Locale.ROOT))
                        && !check(report, "header:" + e.getKey(), e.getValue())) {
                    return report;
                }
            }
        }
        if (jsonBody != null && !jsonBody.isEmpty()) {
            JsonScanner.Result r = JsonScanner.scan(jsonBody, maxJsonDepth, new JsonScanner.Visitor() {
                @Override
                public boolean onKey(String path, String key) {
                    return check(report, "body-key", key);
                }

                @Override
                public boolean onString(String path, String value) {
                    return check(report, safeName(path), value);
                }
            });
            if (r == JsonScanner.Result.TOO_DEEP) {
                report.flag("json-nesting-too-deep");
            } else if (r == JsonScanner.Result.INVALID) {
                check(report, "body", jsonBody);
            }
        }
        return report;
    }

    /** Inspects one value within the budget. @return {@code false} once the budget is exhausted. */
    private boolean check(Report report, String location, String value) {
        if (report.budgetExceeded) {
            return false;
        }
        if (value == null) {
            return true;
        }
        if (++report.values > maxValues) {
            report.flag("too-many-values");
            return false;
        }
        report.chars += value.length();
        if (report.chars > maxInspectedChars) {
            report.flag("inspection-budget-exceeded");
            return false;
        }
        report.add(location, inspector.inspect(value));
        return true;
    }

    public Set<String> getInspectedHeaders() {
        return headers;
    }

    private static String safeName(String name) {
        String n = name == null ? "" : name.replaceAll("[^A-Za-z0-9_.\\[\\]-]", "_");
        return n.length() > 64 ? n.substring(0, 64) : n;
    }

    public static final class Builder {
        private InputInspector inspector = InputInspector.defaults();
        private List<String> headers = DEFAULT_HEADERS;
        private int maxValues = DEFAULT_MAX_VALUES;
        private int maxInspectedChars = DEFAULT_MAX_INSPECTED_CHARS;
        private int maxJsonDepth = DEFAULT_MAX_JSON_DEPTH;

        private Builder() {
        }

        public Builder inspector(InputInspector value) {
            inspector = value;
            return this;
        }

        public Builder headers(List<String> names) {
            headers = new ArrayList<String>(names);
            return this;
        }

        /** Parameter names and values, JSON keys and JSON string values, counted together. */
        public Builder maxValues(int value) {
            maxValues = positive(value, "maxValues");
            return this;
        }

        /** Total characters inspected per request, across path, parameters, headers and body. */
        public Builder maxInspectedChars(int value) {
            maxInspectedChars = positive(value, "maxInspectedChars");
            return this;
        }

        public Builder maxJsonDepth(int value) {
            maxJsonDepth = positive(value, "maxJsonDepth");
            return this;
        }

        public HttpRequestInspector build() {
            return new HttpRequestInspector(this);
        }

        private static int positive(int v, String name) {
            if (v < 1) {
                throw new IllegalArgumentException(name + " must be positive");
            }
            return v;
        }
    }

    /** Where each finding came from. Never contains the offending values. */
    public static final class Report {
        private final List<String> locations = new ArrayList<String>();
        private final List<DetectionResult> results = new ArrayList<DetectionResult>();
        private final List<String> limits = new ArrayList<String>();
        private boolean budgetExceeded;
        private int values;
        private long chars;

        void add(String location, DetectionResult r) {
            if (r.isSuspicious()) {
                locations.add(location);
                results.add(r);
            }
        }

        void flag(String limit) {
            budgetExceeded = true;
            limits.add(limit);
        }

        /** A limit was hit, so part of the request was not inspected. Treated as malicious (fail closed). */
        public boolean isBudgetExceeded() {
            return budgetExceeded;
        }

        /** Each location is scored on its own, so harmless MEDIUM hits in different fields do not add up. */
        public boolean isMalicious() {
            if (budgetExceeded) {
                return true;
            }
            for (DetectionResult r : results) {
                if (r.isMalicious()) {
                    return true;
                }
            }
            return false;
        }

        public boolean isSuspicious() {
            return budgetExceeded || !results.isEmpty();
        }

        public List<Finding> getFindings() {
            return DetectionResult.merge(results).getFindings();
        }

        /** e.g. {@code param:id=[SQLI_PG_SLEEP[HIGH]], header:User-Agent=[...]} */
        public String summary() {
            StringBuilder sb = new StringBuilder();
            for (String l : limits) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(l);
            }
            for (int i = 0; i < locations.size(); i++) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(locations.get(i)).append('=').append(results.get(i).getFindings());
            }
            return sb.toString();
        }
    }
}
