package io.github.wahindra.secure.servlet.jakarta;

import io.github.wahindra.secure.web.CorsPolicy;
import io.github.wahindra.secure.web.RateLimiter;
import io.github.wahindra.secure.web.SecurityEvent;
import io.github.wahindra.secure.web.SecurityFilterEngine;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The filter end to end through the servlet API, with in-memory request and response objects. */
class SecurityFilterTest {

    // ---------------------------------------------------------------- tiny servlet fakes

    static final class Request {
        String method = "GET";
        String uri = "/api/orders";
        final Map<String, String> headers = new LinkedHashMap<String, String>();
        final Map<String, String[]> params = new LinkedHashMap<String, String[]>();
        byte[] body = new byte[0];

        Request method(String m) { method = m; return this; }
        Request uri(String u) { uri = u; return this; }
        Request header(String k, String v) { headers.put(k, v); return this; }
        Request param(String k, String v) { params.put(k, new String[] {v}); return this; }

        Request json(String json) {
            method = "POST";
            body = json.getBytes(StandardCharsets.UTF_8);
            headers.put("Content-Type", "application/json");
            headers.put("Content-Length", String.valueOf(body.length));
            return this;
        }

        HttpServletRequest proxy() {
            final InputStream in = new ByteArrayInputStream(body);
            final ServletInputStream sin = new ServletInputStream() {
                @Override public int read() throws IOException { return in.read(); }
                @Override public boolean isFinished() { return false; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener l) { }
            };
            return (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {HttpServletRequest.class},
                    (p, m, a) -> {
                        switch (m.getName()) {
                            case "getMethod": return method;
                            case "getRequestURI": return uri;
                            case "getRemoteAddr": return "10.0.0.7";
                            case "getHeader": return header((String) a[0]);
                            case "getHeaderNames": return Collections.enumeration(headers.keySet());
                            case "getParameterMap": return params;
                            case "getContentType": return header("Content-Type");
                            case "getContentLengthLong": return header("Content-Length") == null ? -1L : Long.parseLong(header("Content-Length"));
                            case "getCharacterEncoding": return null;
                            case "getInputStream": return sin;
                            case "getAttribute": return null;
                            default: throw new UnsupportedOperationException(m.getName());
                        }
                    });
        }

        private String header(String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    return e.getValue();
                }
            }
            return null;
        }
    }

    static final class Response {
        int status = 200;
        final Map<String, String> headers = new LinkedHashMap<String, String>();
        final StringWriter body = new StringWriter();

        HttpServletResponse proxy() {
            final PrintWriter writer = new PrintWriter(body);
            return (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {HttpServletResponse.class},
                    (p, m, a) -> {
                        switch (m.getName()) {
                            case "setHeader": headers.put((String) a[0], (String) a[1]); return null;
                            case "setStatus": status = (Integer) a[0]; return null;
                            case "isCommitted": return false;
                            case "setContentType": case "setCharacterEncoding": return null;
                            case "getWriter": return writer;
                            default: throw new UnsupportedOperationException(m.getName());
                        }
                    });
        }

        String body() {
            return body.toString();
        }
    }

    /** Records whether the application was reached and what body it read. */
    static final class App implements FilterChain {
        boolean reached;
        String bodySeen;

        @Override
        public void doFilter(ServletRequest request, jakarta.servlet.ServletResponse response) throws IOException {
            reached = true;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InputStream in = request.getInputStream();
            int b;
            while ((b = in.read()) >= 0) {
                out.write(b);
            }
            bodySeen = new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static App run(SecurityFilter f, Request req, Response res) throws Exception {
        App app = new App();
        f.doFilter(req.proxy(), res.proxy(), app);
        return app;
    }

    // ---------------------------------------------------------------- tests

    @Test
    void blocksAttackInQueryParameterAndAddsHeaders() throws Exception {
        Response res = new Response();
        App app = run(new SecurityFilter(), new Request().param("id", "1;SELECT pg_sleep(5)--"), res);
        assertFalse(app.reached);
        assertEquals(400, res.status);
        assertTrue(res.body().contains("\"error\":\"request_rejected\""));
        assertEquals("nosniff", res.headers.get("X-Content-Type-Options"));
    }

    @Test
    void cleanRequestReachesTheAppWithHeaders() throws Exception {
        Response res = new Response();
        App app = run(new SecurityFilter(), new Request().param("id", "42").header("User-Agent", "Mozilla/5.0 (Windows NT 10.0)"), res);
        assertTrue(app.reached);
        assertEquals(200, res.status);
        assertEquals("DENY", res.headers.get("X-Frame-Options"));
    }

    @Test
    void jsonBodyIsInspectedAndThenReplayedUnchanged() throws Exception {
        Response blocked = new Response();
        assertFalse(run(new SecurityFilter(), new Request().json("{\"q\":\"' OR 1=1--\"}"), blocked).reached);
        assertEquals(400, blocked.status);

        String body = "{\"name\":\"O'Brien\",\"items\":[1,2,3]}";
        App app = run(new SecurityFilter(), new Request().json(body), new Response());
        assertTrue(app.reached);
        assertEquals(body, app.bodySeen, "the application must read exactly the original body");
    }

    @Test
    void oversizedJsonBodyIsRejectedInBlockModeAndReplayedInMonitorMode() throws Exception {
        String big = "{\"pad\":\"" + new String(new char[200]).replace('\0', 'a') + "\"}";
        SecurityFilter block = new SecurityFilter(SecurityFilterEngine.builder().maxBodyBytes(100).build());
        Response res = new Response();
        assertFalse(run(block, new Request().json(big), res).reached);
        assertEquals(400, res.status);

        // Chunked body (no Content-Length) larger than the limit: read up to the limit, then replay all of it.
        Request chunked = new Request().json(big);
        chunked.headers.remove("Content-Length");
        SecurityFilter monitor = new SecurityFilter(SecurityFilterEngine.builder().maxBodyBytes(100)
                .mode(SecurityFilterEngine.Mode.MONITOR).build());
        App app = run(monitor, chunked, new Response());
        assertTrue(app.reached);
        assertEquals(big, app.bodySeen);
    }

    @Test
    void rateLimitReturns429WithRetryAfter() throws Exception {
        RateLimiter rl = new RateLimiter(2, Duration.ofMinutes(1), 100, Clock.systemUTC());
        SecurityFilter f = new SecurityFilter(SecurityFilterEngine.builder().rateLimiter(rl).build());
        assertTrue(run(f, new Request(), new Response()).reached);
        assertTrue(run(f, new Request(), new Response()).reached);
        Response limited = new Response();
        assertFalse(run(f, new Request(), limited).reached);
        assertEquals(429, limited.status);
        assertTrue(limited.headers.containsKey("Retry-After"));
        assertTrue(limited.body().contains("rate_limited"));
    }

    @Test
    void corsPreflightIsAnsweredWithoutReachingTheApp() throws Exception {
        SecurityFilter f = new SecurityFilter(SecurityFilterEngine.builder()
                .cors(CorsPolicy.builder().allowOrigins("https://app.example.com").build()).build());
        Response ok = new Response();
        assertFalse(run(f, new Request().method("OPTIONS").header("Origin", "https://app.example.com")
                .header("Access-Control-Request-Method", "POST"), ok).reached);
        assertEquals(204, ok.status);
        assertEquals("https://app.example.com", ok.headers.get("Access-Control-Allow-Origin"));

        Response denied = new Response();
        run(f, new Request().method("OPTIONS").header("Origin", "https://evil.example").header("Access-Control-Request-Method", "POST"), denied);
        assertEquals(403, denied.status);
        assertNull(denied.headers.get("Access-Control-Allow-Origin"));
    }

    @Test
    void monitorModeLetsAttacksThroughButReportsThem() throws Exception {
        List<SecurityEvent> events = new ArrayList<SecurityEvent>();
        SecurityFilter f = new SecurityFilter(SecurityFilterEngine.builder().mode(SecurityFilterEngine.Mode.MONITOR)
                .listener(events::add).build());
        assertTrue(run(f, new Request().param("q", "' OR 1=1--"), new Response()).reached);
        assertEquals(SecurityEvent.Type.REQUEST_FLAGGED, events.get(0).getType());
    }

    @Test
    void webXmlInitParams() throws Exception {
        final Map<String, String> params = new LinkedHashMap<String, String>();
        params.put("mode", "monitor");
        params.put("rateLimitPerMinute", "1");
        params.put("corsAllowedOrigins", "https://app.example.com");
        params.put("securityHeaders", "false");
        final AtomicReference<String> unused = new AtomicReference<String>();
        FilterConfig config = (FilterConfig) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {FilterConfig.class},
                (p, m, a) -> {
                    if ("getInitParameter".equals(m.getName())) {
                        return params.get(a[0]);
                    }
                    if ("getInitParameterNames".equals(m.getName())) {
                        return Collections.enumeration(params.keySet());
                    }
                    unused.set(m.getName());
                    return null;
                });
        SecurityFilter f = new SecurityFilter();
        f.init(config);
        assertEquals(SecurityFilterEngine.Mode.MONITOR, f.getEngine().getMode());
        Response first = new Response();
        assertTrue(run(f, new Request().param("q", "' OR 1=1--"), first).reached, "monitor mode");
        assertNull(first.headers.get("X-Frame-Options"), "securityHeaders=false");
        Response second = new Response();
        run(f, new Request(), second);
        assertEquals(429, second.status, "rateLimitPerMinute=1");
        assertEquals("monitor", params.get("mode").toLowerCase(Locale.ROOT));
    }
}
