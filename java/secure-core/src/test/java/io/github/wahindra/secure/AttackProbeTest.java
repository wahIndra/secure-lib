package io.github.wahindra.secure;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.AttackProbe;
import io.github.wahindra.secure.injection.Encode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Runs the probe against a deliberately vulnerable server on 127.0.0.1. */
class AttackProbeTest {

    private static HttpServer server;
    private static String base;

    @BeforeAll
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // Reflects the parameter without encoding: XSS. Evaluates {{a*b}}: SSTI.
        server.createContext("/search", handler(q -> {
            String body = "<p>Results for " + q + "</p>";
            if (q.matches("\\{\\{\\d+\\*\\d+\\}\\}")) {
                String[] n = q.substring(2, q.length() - 2).split("\\*");
                body = "<p>" + Long.parseLong(n[0]) * Long.parseLong(n[1]) + "</p>";
            }
            return new Object[] {200, body};
        }));
        // Leaks a PostgreSQL error for quotes: error-based SQLi. Sleeps on stacked pg_sleep: time-based.
        server.createContext("/item", handler(id -> {
            if (id.startsWith("1;SELECT pg_sleep(3)")) {
                sleep(3000);
            }
            if (id.contains("'")) {
                return new Object[] {500, "org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near \"'\""};
            }
            return new Object[] {200, "{\"id\":1}"};
        }));
        // Serves files with no base-directory check: path traversal.
        server.createContext("/file", handler(name -> name.contains("etc/passwd")
                ? new Object[] {200, "root:x:0:0:root:/root:/bin/bash\n"}
                : new Object[] {404, "not found"}));
        // The safe version: encodes output, never errors on input.
        server.createContext("/safe", handler(q -> new Object[] {200, "<p>Results for " + Encode.forHtml(q) + "</p>"}));
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    @Test
    void findsReflectedXssAndTemplateInjection() throws IOException {
        Set<String> hits = hits(new AttackProbe.Target(base + "/search?q=FUZZ").only("xss").only("ssti"));
        assertTrue(hits.contains("xss"), hits.toString());
        assertTrue(hits.contains("ssti"), hits.toString());
    }

    @Test
    void findsErrorAndTimeBasedSqlInjection() throws IOException {
        List<AttackProbe.Result> results = AttackProbe.run(new AttackProbe.Target(base + "/item?id=FUZZ").only("sqli"), null);
        Set<String> hits = new TreeSet<String>();
        for (AttackProbe.Result r : results) {
            if (r.getSeverity() == Severity.HIGH) {
                hits.add(r.getCheck());
            }
        }
        assertTrue(hits.contains("sqli-error"), hits.toString());
        assertTrue(hits.contains("sqli-time"), hits.toString());
    }

    @Test
    void findsPathTraversal() throws IOException {
        assertTrue(hits(new AttackProbe.Target(base + "/file?name=FUZZ").only("path")).contains("path"));
    }

    @Test
    void safeEndpointHasNoFindings() throws IOException {
        assertEquals(new TreeSet<String>(), hits(new AttackProbe.Target(base + "/safe?q=FUZZ")));
    }

    private static Set<String> hits(AttackProbe.Target t) throws IOException {
        Set<String> out = new TreeSet<String>();
        for (AttackProbe.Result r : AttackProbe.run(t, null)) {
            if (r.isVulnerable()) {
                out.add(r.getCheck());
            }
        }
        return out;
    }

    interface Logic {
        Object[] apply(String param);
    }

    private static HttpHandler handler(final Logic logic) {
        return new HttpHandler() {
            @Override
            public void handle(HttpExchange ex) throws IOException {
                String query = ex.getRequestURI().getRawQuery();
                String value = query == null ? "" : URLDecoder.decode(query.substring(query.indexOf('=') + 1), "UTF-8");
                Object[] res = logic.apply(value);
                byte[] body = ((String) res[1]).getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders((Integer) res[0], body.length);
                OutputStream os = ex.getResponseBody();
                os.write(body);
                os.close();
            }
        };
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
