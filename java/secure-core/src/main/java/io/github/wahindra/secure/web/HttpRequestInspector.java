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
 * interceptors, JAX-RS filters, Vert.x handlers...). Inspects the path, every parameter name
 * and value, and a configurable set of headers. Request bodies are not read.
 */
public final class HttpRequestInspector {

    public static final List<String> DEFAULT_HEADERS = Collections.unmodifiableList(Arrays.asList(
            "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Original-URL",
            "X-Rewrite-URL", "Origin"));

    private static final int MAX_PARAMETERS = 500;

    private final InputInspector inspector;
    private final Set<String> headers;

    public HttpRequestInspector() {
        this(InputInspector.defaults(), DEFAULT_HEADERS);
    }

    public HttpRequestInspector(InputInspector inspector, List<String> headersToInspect) {
        this.inspector = inspector;
        Set<String> h = new LinkedHashSet<String>();
        for (String name : headersToInspect) {
            h.add(name.toLowerCase(Locale.ROOT));
        }
        this.headers = Collections.unmodifiableSet(h);
    }

    /**
     * @param rawPath    the raw (undecoded) request URI, e.g. {@code getRequestURI()}
     * @param parameters query and form parameters
     * @param headerValues header name to value; names are matched case-insensitively
     */
    public Report inspect(String rawPath, Map<String, String[]> parameters, Map<String, String> headerValues) {
        Report report = new Report();
        // Request paths are always absolute; drop the leading slash so PATH_ABSOLUTE does not fire on every request.
        report.add("path", inspector.inspect(rawPath == null ? null : rawPath.replaceFirst("^/+", "")));
        if (parameters != null) {
            if (parameters.size() > MAX_PARAMETERS) {
                report.tooManyParameters = true;
            }
            int n = 0;
            for (Map.Entry<String, String[]> e : parameters.entrySet()) {
                if (n++ >= MAX_PARAMETERS) {
                    break;
                }
                String name = e.getKey();
                report.add("param-name", inspector.inspect(name));
                if (e.getValue() != null) {
                    for (String v : e.getValue()) {
                        report.add("param:" + safeName(name), inspector.inspect(v));
                    }
                }
            }
        }
        if (headerValues != null) {
            for (Map.Entry<String, String> e : headerValues.entrySet()) {
                if (e.getKey() != null && headers.contains(e.getKey().toLowerCase(Locale.ROOT))) {
                    report.add("header:" + e.getKey(), inspector.inspect(e.getValue()));
                }
            }
        }
        return report;
    }

    public Set<String> getInspectedHeaders() {
        return headers;
    }

    private static String safeName(String name) {
        String n = name == null ? "" : name.replaceAll("[^A-Za-z0-9_.\\[\\]-]", "_");
        return n.length() > 64 ? n.substring(0, 64) : n;
    }

    /** Where each finding came from. Never contains the offending values. */
    public static final class Report {
        private final List<String> locations = new ArrayList<String>();
        private final List<DetectionResult> results = new ArrayList<DetectionResult>();
        private boolean tooManyParameters;

        void add(String location, DetectionResult r) {
            if (r.isSuspicious()) {
                locations.add(location);
                results.add(r);
            }
        }

        /** Each location is scored on its own, so harmless MEDIUM hits in different fields do not add up. */
        public boolean isMalicious() {
            if (tooManyParameters) {
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
            return tooManyParameters || !results.isEmpty();
        }

        public List<Finding> getFindings() {
            return DetectionResult.merge(results).getFindings();
        }

        /** e.g. {@code param:id=[SQLI_PG_SLEEP[HIGH]], header:User-Agent=[...]} */
        public String summary() {
            StringBuilder sb = new StringBuilder();
            if (tooManyParameters) {
                sb.append("too-many-parameters");
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
