package io.github.wahindra.secure.servlet.javax;

import io.github.wahindra.secure.web.CorsPolicy;
import io.github.wahindra.secure.web.HttpRequestInspector;
import io.github.wahindra.secure.web.RateLimiter;
import io.github.wahindra.secure.web.RequestView;
import io.github.wahindra.secure.web.SecurityFilterEngine;
import io.github.wahindra.secure.web.SecurityHeaders;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet adapter for {@link SecurityFilterEngine}: security headers, CORS, rate limiting and
 * inspection of the path, parameters, selected headers and JSON bodies. In {@code BLOCK} mode
 * malicious requests get a generic 400; in {@code MONITOR} mode they are only reported (start
 * here to tune false positives).
 *
 * <p>web.xml init-params, all optional: {@code mode} (block|monitor), {@code headers} (comma list
 * to inspect), {@code securityHeaders} (true|false), {@code failOpen} (true|false),
 * {@code inspectJsonBody} (true|false), {@code maxBodyBytes}, {@code rateLimitPerMinute},
 * {@code corsAllowedOrigins} (comma list), {@code corsAllowCredentials} (true|false).
 *
 * <p>This filter is a safety net. It does not replace parameterized queries, output encoding or
 * access checks in application code.
 */
public class SecurityFilter implements Filter {

    /** Kept for compatibility; same as {@link SecurityFilterEngine.Mode}. */
    public enum Mode { BLOCK, MONITOR }

    private SecurityFilterEngine engine;

    public SecurityFilter() {
        this.engine = SecurityFilterEngine.defaults();
    }

    public SecurityFilter(SecurityFilterEngine engine) {
        this.engine = engine;
    }

    public SecurityFilter(Mode mode, HttpRequestInspector inspector, SecurityHeaders headers, boolean failOpen) {
        this(SecurityFilterEngine.builder()
                .mode(mode == Mode.MONITOR ? SecurityFilterEngine.Mode.MONITOR : SecurityFilterEngine.Mode.BLOCK)
                .inspector(inspector).securityHeaders(headers).failOpen(failOpen).build());
    }

    @Override
    public void init(FilterConfig config) {
        if (config.getInitParameterNames() == null || !config.getInitParameterNames().hasMoreElements()) {
            return;
        }
        SecurityFilterEngine.Builder b = SecurityFilterEngine.builder();
        String m = config.getInitParameter("mode");
        if (m != null) {
            b.mode(SecurityFilterEngine.Mode.valueOf(m.trim().toUpperCase(Locale.ROOT)));
        }
        String h = config.getInitParameter("headers");
        if (h != null) {
            b.inspector(HttpRequestInspector.builder().headers(Arrays.asList(h.trim().split("\\s*,\\s*"))).build());
        }
        String sh = config.getInitParameter("securityHeaders");
        if (sh != null && !Boolean.parseBoolean(sh.trim())) {
            b.securityHeaders(null);
        }
        String fo = config.getInitParameter("failOpen");
        if (fo != null) {
            b.failOpen(Boolean.parseBoolean(fo.trim()));
        }
        String jb = config.getInitParameter("inspectJsonBody");
        if (jb != null) {
            b.inspectJsonBody(Boolean.parseBoolean(jb.trim()));
        }
        String mb = config.getInitParameter("maxBodyBytes");
        if (mb != null) {
            b.maxBodyBytes(Integer.parseInt(mb.trim()));
        }
        String rl = config.getInitParameter("rateLimitPerMinute");
        if (rl != null) {
            b.rateLimiter(RateLimiter.perMinute(Integer.parseInt(rl.trim())));
        }
        String origins = config.getInitParameter("corsAllowedOrigins");
        if (origins != null && !origins.trim().isEmpty()) {
            b.cors(CorsPolicy.builder().allowOrigins(origins.trim().split("\\s*,\\s*"))
                    .allowCredentials(Boolean.parseBoolean(config.getInitParameter("corsAllowCredentials"))).build());
        }
        engine = b.build();
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (!(req instanceof HttpServletRequest) || !(res instanceof HttpServletResponse)) {
            chain.doFilter(req, res);
            return;
        }
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        View view = new View(request);

        HttpServletRequest forward = request;
        byte[] jsonBody = null;
        boolean tooLarge = false;
        if (engine.wantsBody(view)) {
            int max = engine.getMaxBodyBytes();
            long declared = request.getContentLengthLong();
            if (declared > max) {
                tooLarge = true;
            } else {
                byte[] prefix = readUpTo(request.getInputStream(), max + 1);
                tooLarge = prefix.length > max;
                if (!tooLarge) {
                    // Raw bytes: the engine decodes them the way the application parser would.
                    jsonBody = prefix;
                }
                forward = new ReplayingRequest(request, prefix);
            }
        }

        SecurityFilterEngine.Verdict v = engine.evaluateBody(view, jsonBody, tooLarge);
        for (Map.Entry<String, String> e : v.getHeaders().entrySet()) {
            response.setHeader(e.getKey(), e.getValue());
        }
        if (v.isProceed()) {
            chain.doFilter(forward, res);
            return;
        }
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(v.getStatus());
        if (v.getBody() != null) {
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(v.getBody());
        }
    }

    @Override
    public void destroy() {
    }

    /** The engine, e.g. to {@link SecurityFilterEngine#emit} events from application code. */
    public SecurityFilterEngine getEngine() {
        return engine;
    }

    private static Charset charset(HttpServletRequest request) {
        try {
            String enc = request.getCharacterEncoding();
            return enc == null ? StandardCharsets.UTF_8 : Charset.forName(enc);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }

    private static byte[] readUpTo(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 8192));
        byte[] buf = new byte[8192];
        int n;
        while (out.size() < limit && (n = in.read(buf, 0, Math.min(buf.length, limit - out.size()))) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static final class View implements RequestView {
        private final HttpServletRequest r;
        private Map<String, String> headers;

        View(HttpServletRequest r) {
            this.r = r;
        }

        @Override public String method() { return r.getMethod(); }
        @Override public String rawPath() { return r.getRequestURI(); }
        @Override public String remoteAddress() { return r.getRemoteAddr(); }
        @Override public String header(String name) { return r.getHeader(name); }
        @Override public long contentLength() { return r.getContentLengthLong(); }
        @Override public String contentType() { return r.getContentType(); }

        @Override
        public Map<String, String> headers() {
            if (headers == null) {
                headers = new LinkedHashMap<String, String>();
                Enumeration<String> names = r.getHeaderNames();
                while (names != null && names.hasMoreElements()) {
                    String name = names.nextElement();
                    headers.put(name, r.getHeader(name));
                }
            }
            return headers;
        }

        @Override
        public Map<String, String[]> parameters() {
            return r.getParameterMap();
        }
    }

    /** Gives the application the body bytes already read for inspection, then the rest of the stream. */
    private static final class ReplayingRequest extends HttpServletRequestWrapper {
        private final byte[] prefix;
        private ServletInputStream stream;

        ReplayingRequest(HttpServletRequest request, byte[] prefix) {
            super(request);
            this.prefix = prefix;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                final InputStream head = new ByteArrayInputStream(prefix);
                final ServletInputStream rest = super.getInputStream();
                stream = new ServletInputStream() {
                    private boolean headDone;

                    @Override
                    public int read() throws IOException {
                        if (!headDone) {
                            int b = head.read();
                            if (b >= 0) {
                                return b;
                            }
                            headDone = true;
                        }
                        return rest.read();
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        if (!headDone) {
                            int n = head.read(b, off, len);
                            if (n > 0) {
                                return n;
                            }
                            headDone = true;
                        }
                        return rest.read(b, off, len);
                    }

                    @Override
                    public boolean isFinished() {
                        return headDone && rest.isFinished();
                    }

                    @Override
                    public boolean isReady() {
                        return !headDone || rest.isReady();
                    }

                    @Override
                    public void setReadListener(ReadListener listener) {
                        rest.setReadListener(listener);
                    }
                };
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            return new BufferedReader(new InputStreamReader(getInputStream(), charset((HttpServletRequest) getRequest())));
        }
    }
}
