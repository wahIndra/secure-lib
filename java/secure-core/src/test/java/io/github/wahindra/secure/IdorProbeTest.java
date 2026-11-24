package io.github.wahindra.secure;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.IdorProbe;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Runs `secure idor` against deliberately vulnerable and safe endpoints on 127.0.0.1. */
class IdorProbeTest {

    private static final String ALICE_ORDER = "{\"id\":1,\"owner\":\"alice\",\"email\":\"alice@shop.test\"}";
    private static HttpServer server;
    private static String base;

    @BeforeAll
    static void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // Logged-in check only: any valid user gets Alice's order (the IDOR).
        server.createContext("/vuln/orders/1", ex -> {
            String user = user(ex);
            send(ex, user == null ? 401 : 200, user == null ? "" : ALICE_ORDER);
        });
        // No authentication at all.
        server.createContext("/open/orders/1", ex -> send(ex, 200, ALICE_ORDER));
        // Correct: identity from the credential, ownership checked, 404 for others.
        server.createContext("/safe/orders/1", ex -> {
            String user = user(ex);
            send(ex, user == null ? 401 : "alice".equals(user) ? 200 : 404, "alice".equals(user) ? ALICE_ORDER : "");
        });
        // A "my orders" list: each user sees their own data, so bodies differ legitimately.
        server.createContext("/safe/my-orders", ex -> {
            String user = user(ex);
            send(ex, user == null ? 401 : 200, user == null ? "" : "[{\"owner\":\"" + user + "\",\"email\":\"" + user + "@shop.test\"}]");
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    private static IdorProbe.Target target(String path) {
        return new IdorProbe.Target(base + path)
                .ownerHeader("Authorization", "Bearer token-alice")
                .otherHeader("Authorization", "Bearer token-bob");
    }

    @Test
    void findsObjectReadableByAnotherUser() throws IOException {
        List<IdorProbe.Result> r = IdorProbe.run(target("/vuln/orders/1"));
        assertEquals("owner", r.get(0).getAs());
        assertNull(r.get(0).getSeverity());
        assertEquals(Severity.HIGH, r.get(1).getSeverity());
        assertNull(r.get(2).getSeverity(), "anonymous gets 401");
    }

    @Test
    void findsObjectReadableWithoutLogin() throws IOException {
        List<IdorProbe.Result> r = IdorProbe.run(target("/open/orders/1"));
        assertEquals(Severity.HIGH, r.get(1).getSeverity());
        assertEquals(Severity.HIGH, r.get(2).getSeverity());
    }

    @Test
    void safeEndpointHasNoFindings() throws IOException {
        for (IdorProbe.Result r : IdorProbe.run(target("/safe/orders/1"))) {
            assertNull(r.getSeverity(), r.getAs() + ": " + r.getVerdict());
        }
    }

    @Test
    void differentBodyIsMediumWithoutMarkerAndClearedWithMarker() throws IOException {
        assertEquals(Severity.MEDIUM, IdorProbe.run(target("/safe/my-orders")).get(1).getSeverity());
        for (IdorProbe.Result r : IdorProbe.run(target("/safe/my-orders").marker("alice@shop.test"))) {
            assertNull(r.getSeverity(), r.getAs() + ": " + r.getVerdict());
        }
        assertEquals(Severity.HIGH, IdorProbe.run(target("/vuln/orders/1").marker("alice@shop.test")).get(1).getSeverity());
    }

    @Test
    void refusesBadSetup() {
        // Owner can't read it: the URL or the owner's credentials are wrong, so no verdict is possible.
        assertThrows(IOException.class, () -> IdorProbe.run(new IdorProbe.Target(base + "/safe/orders/1")
                .ownerHeader("Authorization", "Bearer token-bob").otherHeader("Authorization", "Bearer token-carol")));
        assertThrows(IllegalArgumentException.class, () -> IdorProbe.run(new IdorProbe.Target(base + "/safe/orders/1")
                .ownerHeader("Authorization", "Bearer token-alice")));
        assertThrows(IllegalArgumentException.class, () -> IdorProbe.run(new IdorProbe.Target("http://93.184.215.14/orders/1")
                .ownerHeader("Authorization", "Bearer a").otherHeader("Authorization", "Bearer b")));
    }

    private static String user(HttpExchange ex) {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        return auth != null && auth.startsWith("Bearer token-") ? auth.substring("Bearer token-".length()) : null;
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
        if (b.length > 0) {
            OutputStream os = ex.getResponseBody();
            os.write(b);
            os.close();
        }
        ex.close();
    }
}
