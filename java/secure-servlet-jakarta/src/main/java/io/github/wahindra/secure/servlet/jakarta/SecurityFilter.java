package io.github.wahindra.secure.servlet.jakarta;

import io.github.wahindra.secure.errors.SafeErrors;
import io.github.wahindra.secure.logging.LogSanitizer;
import io.github.wahindra.secure.web.HttpRequestInspector;
import io.github.wahindra.secure.web.SecurityHeaders;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Adds security headers and inspects every request for injection, XSS, command injection and
 * path traversal probes. In {@code BLOCK} mode malicious requests get a generic 400; in
 * {@code MONITOR} mode they are only logged (start here to tune false positives).
 *
 * <p>web.xml init-params: {@code mode} (block|monitor), {@code headers} (comma list),
 * {@code securityHeaders} (true|false), {@code failOpen} (true|false).
 *
 * <p>This filter is a safety net. It does not replace parameterized queries, output
 * encoding or access checks in application code.
 */
public class SecurityFilter implements Filter {

    public enum Mode { BLOCK, MONITOR }

    private static final Logger LOG = Logger.getLogger(SecurityFilter.class.getName());

    private Mode mode = Mode.BLOCK;
    private HttpRequestInspector inspector = new HttpRequestInspector();
    private SecurityHeaders securityHeaders = SecurityHeaders.defaults();
    private boolean addSecurityHeaders = true;
    private boolean failOpen;

    public SecurityFilter() {
    }

    public SecurityFilter(Mode mode, HttpRequestInspector inspector, SecurityHeaders headers, boolean failOpen) {
        this.mode = mode;
        this.inspector = inspector;
        this.securityHeaders = headers;
        this.addSecurityHeaders = headers != null;
        this.failOpen = failOpen;
    }

    @Override
    public void init(FilterConfig config) {
        String m = config.getInitParameter("mode");
        if (m != null) {
            mode = Mode.valueOf(m.trim().toUpperCase(Locale.ROOT));
        }
        String h = config.getInitParameter("headers");
        if (h != null) {
            inspector = new HttpRequestInspector(io.github.wahindra.secure.InputInspector.defaults(),
                    Arrays.asList(h.trim().split("\\s*,\\s*")));
        }
        String sh = config.getInitParameter("securityHeaders");
        if (sh != null) {
            addSecurityHeaders = Boolean.parseBoolean(sh.trim());
        }
        String fo = config.getInitParameter("failOpen");
        if (fo != null) {
            failOpen = Boolean.parseBoolean(fo.trim());
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (!(req instanceof HttpServletRequest) || !(res instanceof HttpServletResponse)) {
            chain.doFilter(req, res);
            return;
        }
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (addSecurityHeaders && securityHeaders != null) {
            for (Map.Entry<String, String> e : securityHeaders.asMap().entrySet()) {
                response.setHeader(e.getKey(), e.getValue());
            }
        }

        HttpRequestInspector.Report report;
        try {
            report = inspector.inspect(request.getRequestURI(), request.getParameterMap(), headers(request));
        } catch (RuntimeException e) {
            String id = SafeErrors.log(LOG, e, "request inspection failed");
            if (failOpen) {
                chain.doFilter(req, res);
            } else {
                reject(response, id);
            }
            return;
        }

        if (report.isSuspicious()) {
            String id = SafeErrors.newIncidentId();
            boolean block = mode == Mode.BLOCK && report.isMalicious();
            LOG.log(report.isMalicious() ? Level.WARNING : Level.INFO,
                    "security-filter incident=" + id
                            + " action=" + (block ? "blocked" : "allowed")
                            + " method=" + LogSanitizer.sanitize(request.getMethod(), 16)
                            + " uri=" + LogSanitizer.sanitize(request.getRequestURI(), 300)
                            + " remote=" + LogSanitizer.sanitize(request.getRemoteAddr(), 64)
                            + " findings=" + report.summary());
            if (block) {
                reject(response, id);
                return;
            }
        }
        chain.doFilter(req, res);
    }

    @Override
    public void destroy() {
    }

    private static Map<String, String> headers(HttpServletRequest request) {
        Map<String, String> map = new LinkedHashMap<String, String>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            map.put(name, request.getHeader(name));
        }
        return map;
    }

    private static void reject(HttpServletResponse response, String incidentId) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\":\"request_rejected\",\"incidentId\":\"" + incidentId + "\"}");
    }
}
