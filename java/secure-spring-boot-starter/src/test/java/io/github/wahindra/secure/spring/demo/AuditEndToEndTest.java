package io.github.wahindra.secure.spring.demo;

import io.github.wahindra.secure.audit.AuditChain;
import io.github.wahindra.secure.audit.AuditLog;
import io.github.wahindra.secure.spring.Auditor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The audit log in a real app: blocked attacks, access denials, invalid tokens and the app's own
 * actions land in the configured file (hash-chained) and reach a syslog collector.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.application.name=orders-api",
        "secure.identity.provider=keycloak",
        "secure.audit.file.hash-chain=true",
        "secure.audit.syslog.host=127.0.0.1",
        "secure.audit.syslog.protocol=udp",
})
class AuditEndToEndTest {

    private static final DatagramSocket SYSLOG;
    private static final Path DIR;

    static {
        try {
            SYSLOG = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            DIR = Files.createTempDirectory("secure-audit-e2e");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("secure.audit.file.path", () -> DIR.resolve("logs/security-audit.jsonl").toString());
        r.add("secure.audit.syslog.port", SYSLOG::getLocalPort);
    }

    @AfterAll
    static void closeSyslog() {
        SYSLOG.close();
    }

    @Autowired
    private Environment env;
    @Autowired
    private AuditLog audit;
    @Autowired
    private Auditor auditor;

    @Test
    void securityEventsLoginFailuresAndAppActionsAreAudited() throws Exception {
        String base = "http://127.0.0.1:" + env.getProperty("local.server.port");
        String alice = DemoApplication.Tokens.issue("alice", "user");
        HttpClient http = HttpClient.newHttpClient();

        assertEquals(400, Http.get(base + "/api/search?q=%27%20OR%201%3D1--").statusCode());
        assertEquals(403, send(http, base + "/api/orders/2", "Bearer " + alice).statusCode());
        assertEquals(401, send(http, base + "/api/me", "Bearer not-a-real-token").statusCode());
        assertEquals(200, send(http, base + "/api/orders/1/refund", "Bearer " + alice, "POST").statusCode());
        assertTrue(audit.flush(Duration.ofSeconds(5)));

        Path file = DIR.resolve("logs/security-audit.jsonl");
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        String all = String.join("\n", lines);
        assertTrue(all.contains("\"event\":\"REQUEST_BLOCKED\""), all);
        assertTrue(all.contains("\"event\":\"ACCESS_DENIED\"") && all.contains("\"principalId\":\"alice\""), all);
        assertTrue(all.contains("\"event\":\"LOGIN_FAILED\""), "invalid bearer token: " + all);
        assertFalse(all.contains("not-a-real-token"), "a bearer token must never be logged");
        assertTrue(all.contains("\"event\":\"order.refund\""), all);
        String refund = lines.stream().filter(l -> l.contains("order.refund")).findFirst().orElse("");
        assertTrue(refund.contains("\"principalId\":\"alice\"") && refund.contains("\"resource\":\"order/1\"")
                && refund.contains("\"path\":\"/api/orders/1/refund\"") && refund.contains("\"method\":\"POST\""), refund);
        assertTrue(new AuditChain(null).verify(Collections.singletonList(file)).isIntact());

        List<String> syslog = receiveAll();
        assertTrue(syslog.stream().anyMatch(m -> m.matches("^<\\d+>1 \\S+ \\S+ orders-api - order\\.refund - CEF:0\\|wahindra\\|secure\\|1\\|order\\.refund\\|.*")),
                String.join("\n", syslog));
        assertEquals(0, audit.droppedCount());
        assertTrue(auditor.getLog() == audit);
    }

    private static HttpResponse<String> send(HttpClient http, String url, String auth) throws Exception {
        return send(http, url, auth, "GET");
    }

    private static HttpResponse<String> send(HttpClient http, String url, String auth, String method) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Authorization", auth)
                .method(method, HttpRequest.BodyPublishers.noBody()).build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static List<String> receiveAll() throws IOException {
        List<String> out = new ArrayList<>();
        SYSLOG.setSoTimeout(1000);
        byte[] buf = new byte[16384];
        while (true) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                SYSLOG.receive(p);
            } catch (SocketTimeoutException done) {
                return out;
            }
            out.add(new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8));
        }
    }
}
