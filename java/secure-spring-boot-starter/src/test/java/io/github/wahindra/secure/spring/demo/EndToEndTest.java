package io.github.wahindra.secure.spring.demo;

import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.AttackProbe;
import io.github.wahindra.secure.devtools.IdorProbe;
import io.github.wahindra.secure.web.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end: the demo app runs on a real port and is attacked with the library's own developer
 * tools (`secure probe`, `secure idor`), the way a developer would check an app before deploying.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "secure.mode=block",
        "secure.identity.provider=keycloak",
        "secure.identity.client-id=orders-api",
        "secure.cors.allowed-origins=https://app.shop.test",
})
class EndToEndTest {

    private static final String ALICE = DemoApplication.Tokens.issue("alice", "user");
    private static final String BOB = DemoApplication.Tokens.issue("bob", "user");
    private static final String ADMIN = DemoApplication.Tokens.issue("root", "admin");

    @Autowired
    private Environment env;

    private String base;

    @BeforeEach
    void setUp() {
        base = "http://127.0.0.1:" + env.getProperty("local.server.port");
        DemoApplication.EVENTS.clear();
    }

    @Test
    void attackProbeFindsNothingBecauseTheStarterBlocksIt() throws Exception {
        List<AttackProbe.Result> results = AttackProbe.run(new AttackProbe.Target(base + "/api/search?q=FUZZ"), null);
        List<String> found = results.stream().filter(r -> r.getSeverity() == Severity.HIGH || r.getSeverity() == Severity.MEDIUM)
                .map(r -> r.getCheck() + " " + r.getPayload()).collect(Collectors.toList());
        assertTrue(found.isEmpty(), "attacks got through: " + found);
        long blocked = results.stream().filter(r -> r.getVerdict().startsWith("blocked")).count();
        assertTrue(blocked >= 30, "expected most payloads to be blocked, got " + blocked);
        assertTrue(DemoApplication.EVENTS.stream().anyMatch(e -> e.getType() == SecurityEvent.Type.REQUEST_BLOCKED));
    }

    @Test
    void jsonBodyAttackIsBlockedAndCleanBodyReachesTheController() throws Exception {
        HttpResponse<String> attack = Http.send("POST", base + "/api/search", "{\"q\":\"' OR 1=1--\"}", "Content-Type", "application/json");
        assertEquals(400, attack.statusCode());
        assertTrue(attack.body().contains("request_rejected"));
        HttpResponse<String> clean = Http.send("POST", base + "/api/search", "{\"q\":\"shoes\"}", "Content-Type", "application/json");
        assertEquals(200, clean.statusCode());
        assertEquals("<p>Results for shoes</p>", clean.body(), "the body is replayed to Spring unchanged");
    }

    @Test
    void idorCheckPassesOnTheCorrectEndpointAndFailsOnTheBrokenOne() throws Exception {
        for (IdorProbe.Result r : IdorProbe.run(target("/api/orders/1"))) {
            assertNull(r.getSeverity(), r.getAs() + ": " + r.getVerdict());
        }
        List<IdorProbe.Result> broken = IdorProbe.run(target("/api/vuln/orders/1"));
        assertEquals(Severity.HIGH, broken.get(1).getSeverity(), "bob can read alice's order");
        assertNull(broken.get(2).getSeverity(), "anonymous still gets 401 from Spring Security");
        assertTrue(DemoApplication.EVENTS.stream().anyMatch(e -> e.getType() == SecurityEvent.Type.ACCESS_DENIED
                && "bob".equals(e.getPrincipalId())), "bob's denied attempt is reported");
    }

    @Test
    void currentUserComesFromTheKeycloakToken() throws Exception {
        HttpResponse<String> me = Http.get(base + "/api/me", "Authorization", "Bearer " + ALICE);
        assertEquals(200, me.statusCode());
        assertTrue(me.body().contains("\"id\":\"alice\""));
        assertTrue(me.body().contains("order-reader"), "client roles for orders-api are mapped: " + me.body());
        assertEquals(200, Http.get(base + "/api/orders/1", "Authorization", "Bearer " + ADMIN).statusCode(), "admin role overrides ownership");
        HttpResponse<String> denied = Http.get(base + "/api/orders/1", "Authorization", "Bearer " + BOB);
        assertEquals(403, denied.statusCode());
        assertFalse(denied.body().contains("own"), "the reason is never sent to the client");
    }

    @Test
    void securityHeadersCorsAndRedirects() throws Exception {
        HttpResponse<String> r = Http.get(base + "/api/search?q=shoes");
        assertEquals("nosniff", r.headers().firstValue("X-Content-Type-Options").orElse(null));
        assertTrue(r.headers().firstValue("Content-Security-Policy").isPresent());

        HttpResponse<String> pre = Http.send("OPTIONS", base + "/api/search", null, "Origin", "https://app.shop.test",
                "Access-Control-Request-Method", "POST");
        assertEquals(204, pre.statusCode());
        assertEquals("https://app.shop.test", pre.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
        HttpResponse<String> evil = Http.send("OPTIONS", base + "/api/search", null, "Origin", "https://evil.test",
                "Access-Control-Request-Method", "POST");
        assertEquals(403, evil.statusCode());

        assertEquals("/", Http.get(base + "/go?next=https://evil.test").headers().firstValue("Location").orElse(null));
        assertEquals("/orders", Http.get(base + "/go?next=/orders").headers().firstValue("Location").orElse(null));
    }

    private IdorProbe.Target target(String path) {
        return new IdorProbe.Target(base + path)
                .ownerHeader("Authorization", "Bearer " + ALICE)
                .otherHeader("Authorization", "Bearer " + BOB)
                .marker("alice@shop.test");
    }
}
