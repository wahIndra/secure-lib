package io.github.wahindra.secure;

import io.github.wahindra.secure.crypto.LoginAttemptLimiter;
import io.github.wahindra.secure.web.CorsPolicy;
import io.github.wahindra.secure.web.HttpRequestInspector;
import io.github.wahindra.secure.web.RateLimiter;
import io.github.wahindra.secure.web.RequestView;
import io.github.wahindra.secure.web.SafeRedirect;
import io.github.wahindra.secure.web.SecurityEvent;
import io.github.wahindra.secure.web.SecurityEventListener;
import io.github.wahindra.secure.web.SecurityFilterEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiProtectionTest {

    // ---------------------------------------------------------------- JSON bodies and inspection budget

    private final HttpRequestInspector inspector = new HttpRequestInspector();

    @Test
    void jsonBodyValuesAndKeysAreInspected() {
        assertTrue(inspector.inspect("/api", null, null, "{\"filter\":{\"name\":\"1;SELECT pg_sleep(5)--\"}}").isMalicious());
        assertTrue(inspector.inspect("/api", null, null, "{\"items\":[\"ok\",\"' OR 1=1--\"]}").isMalicious());
        assertTrue(inspector.inspect("/api", null, null, "{\"<script>alert(1)</script>\":1}").isMalicious(), "keys too");
        assertTrue(inspector.inspect("/api", null, null, "{\"q\":\"\\u0027 OR 1=1--\"}").isMalicious(), "unicode escapes decoded");
        assertFalse(inspector.inspect("/api", null, null, "{\"name\":\"O'Brien\",\"qty\":3,\"vip\":true,\"note\":null}").isSuspicious());
    }

    @Test
    void invalidJsonIsInspectedAsTextSoItCannotBypass() {
        assertTrue(inspector.inspect("/api", null, null, "{\"q\": \"x\" ' OR 1=1-- ").isMalicious());
    }

    @Test
    void deepNestingIsRejectedNotSkipped() {
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            deep.append("{\"a\":");
        }
        deep.append("\"' OR 1=1--\"");
        for (int i = 0; i < 30; i++) {
            deep.append('}');
        }
        HttpRequestInspector.Report r = inspector.inspect("/api", null, null, deep.toString());
        assertTrue(r.isMalicious());
        assertTrue(r.summary().contains("json-nesting-too-deep"));
    }

    @Test
    void budgetStopsPaddingAndHugeRequests() {
        HttpRequestInspector small = HttpRequestInspector.builder().maxInspectedChars(1000).maxValues(10).build();
        Map<String, String[]> padded = new LinkedHashMap<String, String[]>();
        padded.put("pad", new String[] {repeat('a', 2000)});
        padded.put("q", new String[] {"' OR 1=1--"});
        HttpRequestInspector.Report r = small.inspect("/x", padded, null);
        assertTrue(r.isMalicious() && r.isBudgetExceeded());
        assertTrue(r.summary().contains("inspection-budget-exceeded"));

        Map<String, String[]> many = new LinkedHashMap<String, String[]>();
        for (int i = 0; i < 20; i++) {
            many.put("p" + i, new String[] {"v"});
        }
        assertTrue(small.inspect("/x", many, null).summary().contains("too-many-values"));
        assertFalse(new HttpRequestInspector().inspect("/x", many, null).isSuspicious());
    }

    @Test
    void defaultBudgetKeepsWorstCaseFast() {
        Map<String, String[]> huge = new LinkedHashMap<String, String[]>();
        for (int i = 0; i < 500; i++) {
            huge.put("p" + i, new String[] {repeat('x', 65536)});
        }
        long start = System.nanoTime();
        HttpRequestInspector.Report r = new HttpRequestInspector().inspect("/x", huge, null);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(r.isBudgetExceeded());
        assertTrue(ms < 1000, "500 x 64 KB must stop at the budget, took " + ms + " ms");
    }

    // ---------------------------------------------------------------- rate limiting

    @Test
    void rateLimiterAllowsBurstThenRefills() {
        MutableClock clock = new MutableClock();
        RateLimiter rl = new RateLimiter(3, Duration.ofSeconds(3), 1000, clock);
        assertTrue(rl.tryAcquire("ip-1").isAllowed());
        assertTrue(rl.tryAcquire("ip-1").isAllowed());
        RateLimiter.Decision third = rl.tryAcquire("ip-1");
        assertTrue(third.isAllowed());
        assertEquals(0, third.getRemaining());
        RateLimiter.Decision denied = rl.tryAcquire("ip-1");
        assertFalse(denied.isAllowed());
        assertEquals("1", denied.retryAfterSeconds());
        assertEquals("1", denied.headers().get("Retry-After"));
        assertTrue(rl.tryAcquire("ip-2").isAllowed(), "keys are independent");
        clock.advance(Duration.ofSeconds(1));
        assertTrue(rl.tryAcquire("ip-1").isAllowed(), "one token refilled per second");
        assertFalse(rl.tryAcquire("ip-1").isAllowed());
    }

    @Test
    void rateLimiterMemoryIsBounded() {
        RateLimiter rl = new RateLimiter(5, Duration.ofSeconds(1), 100, new MutableClock());
        for (int i = 0; i < 10_000; i++) {
            rl.tryAcquire("k" + i);
        }
        assertEquals(100, rl.trackedKeys());
    }

    // ---------------------------------------------------------------- redirects

    @ParameterizedTest
    @ValueSource(strings = {
            "https://evil.example", "//evil.example", "/\\evil.example", "\\\\evil.example", "/%2F%2Fevil.example",
            "/%5cevil.example", "javascript:alert(1)", "data:text/html,x", "https://accounts.example.com@evil.example",
            "https://evil.example/?https://accounts.example.com", "/ok\r\nSet-Cookie: x=1", "http://accounts.example.com.evil.example",
            " ", "https:evil.example"
    })
    void unsafeRedirectsFallBack(String target) {
        assertEquals("/", SafeRedirect.target(target, "/", "accounts.example.com", "*.shop.example"));
    }

    @Test
    void safeRedirectsAreKept() {
        assertEquals("/orders/42?tab=items", SafeRedirect.target("/orders/42?tab=items", "/"));
        assertEquals("https://accounts.example.com/profile", SafeRedirect.target("https://accounts.example.com/profile", "/", "accounts.example.com"));
        assertEquals("https://eu.shop.example/", SafeRedirect.target("https://eu.shop.example/", "/", "*.shop.example"));
        assertEquals("/", SafeRedirect.target("https://shop.example/", "/", "*.shop.example"), "wildcard needs a subdomain");
        assertEquals("/home", SafeRedirect.target(null, "/home"));
    }

    // ---------------------------------------------------------------- CORS

    private final CorsPolicy cors = CorsPolicy.builder()
            .allowOrigins("https://app.example.com", "https://*.admin.example.com")
            .allowMethods("GET", "POST", "DELETE")
            .allowCredentials(true)
            .build();

    @Test
    void corsAllowsListedOriginsOnly() {
        CorsPolicy.Result ok = cors.evaluate("https://app.example.com", "GET", null, null);
        assertTrue(ok.isAllowed());
        assertEquals("https://app.example.com", ok.getHeaders().get("Access-Control-Allow-Origin"));
        assertEquals("true", ok.getHeaders().get("Access-Control-Allow-Credentials"));
        assertEquals("Origin", ok.getHeaders().get("Vary"));
        assertTrue(cors.evaluate("https://eu.admin.example.com", "GET", null, null).isAllowed());

        for (String bad : new String[] {"https://evil.example", "null", "https://app.example.com.evil.example",
                "https://admin.example.com", "http://app.example.com", "https://app.example.com/path", "https://evilapp.example.com"}) {
            CorsPolicy.Result r = cors.evaluate(bad, "GET", null, null);
            assertFalse(r.isAllowed(), bad);
            assertNull(r.getHeaders().get("Access-Control-Allow-Origin"), bad);
        }
        assertTrue(cors.evaluate(null, "GET", null, null).isAllowed(), "no Origin: not a CORS request");
    }

    @Test
    void corsPreflight() {
        CorsPolicy.Result pre = cors.evaluate("https://app.example.com", "OPTIONS", "DELETE", "content-type, authorization");
        assertTrue(pre.isPreflight() && pre.isAllowed());
        assertEquals("GET, POST, DELETE", pre.getHeaders().get("Access-Control-Allow-Methods"));
        assertFalse(cors.evaluate("https://app.example.com", "OPTIONS", "PUT", null).isAllowed(), "method not listed");
        assertFalse(cors.evaluate("https://app.example.com", "OPTIONS", "GET", "x-evil").isAllowed(), "header not listed");
        assertFalse(cors.evaluate("https://evil.example", "OPTIONS", "GET", null).isAllowed());
    }

    @Test
    void corsRefusesWildcardWithCredentials() {
        assertThrows(IllegalArgumentException.class, () -> CorsPolicy.builder().allowOrigins("*").allowCredentials(true).build());
        assertEquals("*", CorsPolicy.builder().allowOrigins("*").build()
                .evaluate("https://any.example", "GET", null, null).getHeaders().get("Access-Control-Allow-Origin"));
    }

    // ---------------------------------------------------------------- engine and events

    private static final class Req implements RequestView {
        final String method;
        final String path;
        final Map<String, String> headers = new HashMap<String, String>();
        final Map<String, String[]> params = new HashMap<String, String[]>();

        Req(String method, String path) {
            this.method = method;
            this.path = path;
        }

        Req header(String k, String v) {
            headers.put(k.toLowerCase(Locale.ROOT), v);
            return this;
        }

        Req param(String k, String v) {
            params.put(k, new String[] {v});
            return this;
        }

        @Override public String method() { return method; }
        @Override public String rawPath() { return path; }
        @Override public String remoteAddress() { return "10.0.0.7"; }
        @Override public String header(String name) { return headers.get(name.toLowerCase(Locale.ROOT)); }
        @Override public Map<String, String> headers() { return headers; }
        @Override public Map<String, String[]> parameters() { return params; }
    }

    @Test
    void engineBlocksMonitorsAndEmitsEvents() {
        List<SecurityEvent> events = new ArrayList<SecurityEvent>();
        SecurityFilterEngine block = SecurityFilterEngine.builder().listener(events::add).build();
        SecurityFilterEngine.Verdict v = block.evaluate(new Req("GET", "/api/orders").param("id", "1;SELECT pg_sleep(5)--"), null, false);
        assertFalse(v.isProceed());
        assertEquals(400, v.getStatus());
        assertTrue(v.getBody().contains("request_rejected"));
        assertEquals("nosniff", v.getHeaders().get("X-Content-Type-Options"));
        assertEquals(SecurityEvent.Type.REQUEST_BLOCKED, events.get(0).getType());
        assertTrue(events.get(0).getRuleIds().contains("SQLI_PG_SLEEP"));
        assertEquals(OwaspCategory.INJECTION, events.get(0).getCategory());
        assertFalse(events.get(0).toJson().contains("pg_sleep(5)"), "events never carry the payload");

        events.clear();
        SecurityFilterEngine monitor = SecurityFilterEngine.builder().mode(SecurityFilterEngine.Mode.MONITOR).listener(events::add).build();
        assertTrue(monitor.evaluate(new Req("GET", "/api").param("id", "' OR 1=1--"), null, false).isProceed());
        assertEquals(SecurityEvent.Type.REQUEST_FLAGGED, events.get(0).getType());

        events.clear();
        assertTrue(block.evaluate(new Req("GET", "/api/orders").param("id", "42"), null, false).isProceed());
        assertTrue(events.isEmpty());
    }

    @Test
    void engineJsonBodyAndOversizedBody() {
        SecurityFilterEngine engine = SecurityFilterEngine.builder().maxBodyBytes(100).build();
        Req post = new Req("POST", "/api/search").header("Content-Type", "application/json; charset=utf-8").header("Content-Length", "20");
        assertTrue(engine.wantsBody(post));
        assertFalse(engine.wantsBody(new Req("GET", "/x").header("Content-Type", "application/json").header("Content-Length", "0")), "GET without a body");
        assertFalse(engine.wantsBody(new Req("POST", "/x").header("Content-Type", "multipart/form-data").header("Content-Length", "9")));
        assertEquals(400, engine.evaluate(post, "{\"q\":\"' OR 1=1--\"}", false).getStatus());
        assertTrue(engine.evaluate(post, "{\"q\":\"shoes\"}", false).isProceed());
        assertEquals(400, engine.evaluate(post, null, true).getStatus(), "too large to inspect: fail closed");
    }

    /** Inspection must read the body the way Jackson does, or an encoded payload slips through. */
    @Test
    void jsonBodyEncodingCannotHidePayloads() throws Exception {
        SecurityFilterEngine engine = SecurityFilterEngine.defaults();
        String attack = "{\"q\":\"' OR 1=1--\"}";
        Map<String, java.nio.charset.Charset> encodings = new LinkedHashMap<String, java.nio.charset.Charset>();
        encodings.put("UTF-16LE", java.nio.charset.StandardCharsets.UTF_16LE);
        encodings.put("UTF-16BE", java.nio.charset.StandardCharsets.UTF_16BE);
        encodings.put("UTF-32LE", java.nio.charset.Charset.forName("UTF-32LE"));
        encodings.put("UTF-32BE", java.nio.charset.Charset.forName("UTF-32BE"));
        for (Map.Entry<String, java.nio.charset.Charset> e : encodings.entrySet()) {
            byte[] noBom = attack.getBytes(e.getValue());
            // No charset declared (Jackson auto-detects), a mismatching one, and the honest one.
            for (String ct : new String[] {"application/json", "application/json; charset=utf-8", "application/json; charset=" + e.getKey()}) {
                Req post = new Req("POST", "/api").header("Content-Type", ct).header("Content-Length", String.valueOf(noBom.length));
                assertEquals(400, engine.evaluateBody(post, noBom, false).getStatus(), e.getKey() + " / " + ct);
            }
        }
        // With a byte order mark.
        byte[] bom = ("﻿" + attack).getBytes(java.nio.charset.StandardCharsets.UTF_16BE);
        assertEquals(400, engine.evaluateBody(new Req("POST", "/api").header("Content-Type", "application/json")
                .header("Content-Length", "1"), bom, false).getStatus());
        // Clean UTF-16 bodies still pass.
        byte[] clean = "{\"q\":\"shoes\"}".getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
        assertTrue(engine.evaluateBody(new Req("POST", "/api").header("Content-Type", "application/json")
                .header("Content-Length", "1"), clean, false).isProceed());
    }

    @Test
    void undecodableJsonBodyIsRejected() {
        byte[] invalidUtf8 = new byte[] {'{', '"', 'q', '"', ':', '"', (byte) 0xc3, (byte) 0x28, '"', '}'};
        SecurityFilterEngine.Verdict v = SecurityFilterEngine.defaults().evaluateBody(
                new Req("POST", "/api").header("Content-Type", "application/json; charset=utf-8").header("Content-Length", "10"), invalidUtf8, false);
        assertEquals(400, v.getStatus());
    }

    @Test
    void jsonBodyOnGetIsInspectedToo() {
        SecurityFilterEngine engine = SecurityFilterEngine.defaults();
        Req get = new Req("GET", "/api/search").header("Content-Type", "application/json").header("Content-Length", "20");
        assertTrue(engine.wantsBody(get), "Spring binds @RequestBody on GET");
        assertEquals(400, engine.evaluateBody(get, "{\"q\":\"' OR 1=1--\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8), false).getStatus());
        assertFalse(engine.wantsBody(new Req("GET", "/api/search").header("Content-Type", "application/json").header("Content-Length", "0")), "no body: nothing to read");
        assertTrue(engine.wantsBody(new Req("POST", "/x").header("Content-Type", "application/json").header("Transfer-Encoding", "chunked")));
    }

    /** HTTP/2 needs neither Content-Length nor Transfer-Encoding, and the app still parses the body. */
    @Test
    void jsonBodyOfUnknownLengthIsRead() {
        SecurityFilterEngine engine = SecurityFilterEngine.defaults();
        Req h2 = new Req("POST", "/api/search").header("Content-Type", "application/json");
        assertTrue(engine.wantsBody(h2), "unknown length must be read");
        assertTrue(engine.wantsBody(new Req("POST", "/api/search").header("Content-Type", "application/json")
                .header("Content-Length", "0").header("Transfer-Encoding", "chunked")), "Transfer-Encoding overrides Content-Length: 0");
        assertEquals(400, engine.evaluateBody(h2, "{\"q\":\"' OR 1=1--\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8), false).getStatus());
        assertTrue(engine.evaluateBody(new Req("GET", "/api/search").header("Content-Type", "application/json"), new byte[0], false).isProceed(),
                "reading turned up no body: the request passes");
    }

    /** The app may decode the declared charset leniently; a reading that fails strictly is rejected, not dropped. */
    @Test
    void bodyThatFailsTheDeclaredCharsetIsRejected() {
        byte[] utf8 = "{\"q\":\"café\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        SecurityFilterEngine engine = SecurityFilterEngine.defaults();
        assertTrue(engine.evaluateBody(new Req("POST", "/api").header("Content-Type", "application/json; charset=utf-8")
                .header("Content-Length", "1"), utf8, false).isProceed(), "honest declaration passes");
        assertEquals(400, engine.evaluateBody(new Req("POST", "/api").header("Content-Type", "application/json; charset=us-ascii")
                .header("Content-Length", "1"), utf8, false).getStatus(), "declared charset cannot decode it");
    }

    @Test
    void engineRateLimitAndCors() {
        List<SecurityEvent> events = new ArrayList<SecurityEvent>();
        SecurityFilterEngine engine = SecurityFilterEngine.builder()
                .rateLimiter(new RateLimiter(2, Duration.ofMinutes(1), 100, new MutableClock()))
                .cors(cors).listener(events::add).build();
        assertTrue(engine.evaluate(new Req("GET", "/a"), null, false).isProceed());
        SecurityFilterEngine.Verdict second = engine.evaluate(new Req("GET", "/a"), null, false);
        assertEquals("0", second.getHeaders().get("RateLimit-Remaining"));
        SecurityFilterEngine.Verdict limited = engine.evaluate(new Req("GET", "/a"), null, false);
        assertEquals(429, limited.getStatus());
        assertTrue(limited.getHeaders().containsKey("Retry-After"));
        assertEquals(SecurityEvent.Type.RATE_LIMITED, events.get(events.size() - 1).getType());

        SecurityFilterEngine corsOnly = SecurityFilterEngine.builder().cors(cors).listener(events::add).build();
        SecurityFilterEngine.Verdict pre = corsOnly.evaluate(new Req("OPTIONS", "/a").header("Origin", "https://app.example.com")
                .header("Access-Control-Request-Method", "POST"), null, false);
        assertEquals(204, pre.getStatus());
        assertEquals("https://app.example.com", pre.getHeaders().get("Access-Control-Allow-Origin"));
        SecurityFilterEngine.Verdict denied = corsOnly.evaluate(new Req("OPTIONS", "/a").header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "POST"), null, false);
        assertEquals(403, denied.getStatus());
        assertEquals(SecurityEvent.Type.CORS_REJECTED, events.get(events.size() - 1).getType());
    }

    @Test
    void brokenListenerNeverBreaksTheRequest() {
        SecurityEventListener broken = e -> {
            throw new IllegalStateException("siem down");
        };
        SecurityFilterEngine engine = SecurityFilterEngine.builder().listener(broken).build();
        assertEquals(400, engine.evaluate(new Req("GET", "/a").param("q", "' OR 1=1--"), null, false).getStatus());
    }

    @Test
    void eventJsonIsSanitizedAndComplete() {
        String json = SecurityEvent.builder(SecurityEvent.Type.ACCESS_DENIED, "id-1").timestamp(Instant.parse("2026-11-24T00:00:00Z"))
                .method("GET").path("/api/orders/9\r\nforged").principalId("alice").category(OwaspCategory.BROKEN_ACCESS_CONTROL)
                .ruleId("IDOR").detail("caller does not own resource").build().toJson();
        assertTrue(json.startsWith("{\"type\":\"ACCESS_DENIED\",\"incidentId\":\"id-1\",\"timestamp\":\"2026-11-24T00:00:00Z\""), json);
        assertTrue(json.contains("\"owasp\":\"A01:2025\""));
        assertFalse(json.contains("\r") || json.contains("\n"));
    }

    @Test
    void loginLockoutEmitsEvent() {
        List<SecurityEvent> events = Collections.synchronizedList(new ArrayList<SecurityEvent>());
        LoginAttemptLimiter l = new LoginAttemptLimiter(2, Duration.ofMinutes(5), Duration.ofMinutes(10), 100, new MutableClock())
                .onLockout(events::add);
        l.recordFailure("alice");
        assertTrue(events.isEmpty());
        l.recordFailure("alice");
        assertEquals(1, events.size());
        assertEquals(SecurityEvent.Type.LOGIN_LOCKED, events.get(0).getType());
        assertEquals("alice", events.get(0).getPrincipalId());
    }

    private static String repeat(char c, int n) {
        char[] a = new char[n];
        java.util.Arrays.fill(a, c);
        return new String(a);
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
