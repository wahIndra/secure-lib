package io.github.wahindra.secure;

import io.github.wahindra.secure.crypto.LoginAttemptLimiter;
import io.github.wahindra.secure.crypto.PasswordHasher;
import io.github.wahindra.secure.crypto.PasswordPolicy;
import io.github.wahindra.secure.crypto.SecureTokens;
import io.github.wahindra.secure.injection.Encode;
import io.github.wahindra.secure.injection.SafeCommand;
import io.github.wahindra.secure.injection.SafeSql;
import io.github.wahindra.secure.integrity.HmacSigner;
import io.github.wahindra.secure.integrity.SafeObjectInputStream;
import io.github.wahindra.secure.logging.LogSanitizer;
import io.github.wahindra.secure.web.CsrfTokenService;
import io.github.wahindra.secure.web.HttpRequestInspector;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidClassException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoAndWebTest {

    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    void passwordHashing() {
        PasswordHasher h = new PasswordHasher(1000);
        String stored = h.hash("correct horse battery".toCharArray());
        assertTrue(stored.startsWith("pbkdf2_sha256$1000$"));
        assertTrue(h.verify("correct horse battery".toCharArray(), stored));
        assertFalse(h.verify("wrong".toCharArray(), stored));
        assertFalse(h.verify("x".toCharArray(), "garbage"));
        assertFalse(h.verify("x".toCharArray(), "pbkdf2_sha256$999999999$AAAA$AAAA"));
        assertNotEquals(stored, h.hash("correct horse battery".toCharArray()));
        assertTrue(new PasswordHasher().needsRehash(stored));
    }

    /** Hash produced by the JavaScript package; both implementations must agree. */
    @Test
    void verifiesJavaScriptHash() {
        String fromJs = CrossLanguage.JS_HASH;
        assertTrue(new PasswordHasher(1000).verify("correct horse battery".toCharArray(), fromJs));
    }

    @Test
    void passwordPolicy() {
        PasswordPolicy p = new PasswordPolicy();
        assertTrue(p.isAcceptable("glacier-lantern-91".toCharArray(), "alice"));
        assertFalse(p.isAcceptable("short".toCharArray(), "alice"));
        assertFalse(p.isAcceptable("password123!".toCharArray(), "alice"));
        assertFalse(p.isAcceptable("alice-is-great-2026".toCharArray(), "alice"));
        assertFalse(p.isAcceptable("aaaaaaaaaaaaaa".toCharArray(), "bob"));
    }

    @Test
    void loginLimiter() {
        MutableClock clock = new MutableClock();
        LoginAttemptLimiter l = new LoginAttemptLimiter(3, Duration.ofMinutes(5), Duration.ofMinutes(10), 100, clock);
        l.recordFailure("alice");
        l.recordFailure("alice");
        assertFalse(l.isLocked("alice"));
        l.recordFailure("alice");
        assertTrue(l.isLocked("alice"));
        assertEquals(Duration.ofMinutes(10), l.retryAfter("alice"));
        clock.advance(Duration.ofMinutes(11));
        assertFalse(l.isLocked("alice"));
    }

    @Test
    void tokensAndHmac() {
        assertEquals(43, SecureTokens.urlSafe().length());
        assertTrue(SecureTokens.constantTimeEquals("abc", "abc"));
        assertFalse(SecureTokens.constantTimeEquals("abc", "abd"));
        HmacSigner s = new HmacSigner(KEY);
        String sig = s.sign("user=42");
        assertTrue(s.verify("user=42", sig));
        assertFalse(s.verify("user=43", sig));
        assertThrows(IllegalArgumentException.class, () -> new HmacSigner(new byte[8]));
        assertEquals(CrossLanguage.HMAC_OF_HELLO, s.sign("hello"));
    }

    @Test
    void csrf() {
        CsrfTokenService csrf = new CsrfTokenService(KEY);
        String t = csrf.generate("session-1");
        assertTrue(csrf.verify("session-1", t));
        assertFalse(csrf.verify("session-2", t));
        assertFalse(csrf.verify("session-1", t + "x"));
        assertFalse(csrf.verify("session-1", "nodot"));
        assertTrue(CsrfTokenService.requiresToken("POST"));
        assertFalse(CsrfTokenService.requiresToken("GET"));
    }

    @Test
    void encoders() {
        assertEquals("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;", Encode.forHtml("<script>alert(1)</script>"));
        assertEquals("a&#x22;&#x20;onmouseover&#x3d;x", Encode.forHtmlAttribute("a\" onmouseover=x"));
        assertEquals("\\x27\\x3b alert\\x281\\x29\\x3c\\x2fscript\\x3e", Encode.forJavaScript("'; alert(1)</script>"));
        assertEquals("a%20b%26c%3Dd", Encode.forUrlComponent("a b&c=d"));
        assertEquals("#", Encode.safeUrl("javascript:alert(1)"));
        assertEquals("#", Encode.safeUrl(" Java\tScript:alert(1)"));
        assertEquals("https://x.example/a", Encode.safeUrl("https://x.example/a"));
        assertEquals("/relative?a=1", Encode.safeUrl("/relative?a=1"));
    }

    @Test
    void safeSql() {
        assertEquals("created_at", SafeSql.allowlisted("CREATED_AT", Arrays.asList("created_at", "total")));
        assertThrows(SecurityViolationException.class,
                () -> SafeSql.allowlisted("total; DROP TABLE x", Arrays.asList("created_at", "total")));
        assertEquals("DESC", SafeSql.direction("desc"));
        assertEquals("ASC", SafeSql.direction("1;drop"));
        assertEquals("?, ?, ?", SafeSql.placeholders(3));
        assertEquals("100\\%\\_off\\\\", SafeSql.escapeLike("100%_off\\"));
        assertThrows(SecurityViolationException.class, () -> SafeSql.quoteIdentifier("a\"b"));
        assertEquals(50, SafeSql.clamp("99999", 1, 50, 20));
        Map<String, String> cols = new HashMap<String, String>();
        cols.put("created", "o.created_at");
        assertEquals("o.created_at", SafeSql.mapped("Created", cols));
    }

    @Test
    void safeCommand() {
        assertEquals(Arrays.asList("/usr/bin/convert", "in.png", "out.jpg"),
                SafeCommand.of("/usr/bin/convert").arg("in.png").arg("out.jpg").toList());
        assertThrows(SecurityViolationException.class, () -> SafeCommand.of("/bin/sh"));
        assertThrows(SecurityViolationException.class, () -> SafeCommand.of("convert").arg("a;rm -rf /"));
        assertThrows(SecurityViolationException.class, () -> SafeCommand.of("tar").arg("--checkpoint-action=exec=sh"));
    }

    @Test
    void logSanitizer() {
        assertEquals("user=bob\\nINFO fake entry", LogSanitizer.sanitize("user=bob\nINFO fake entry"));
        assertEquals("password=**** next", LogSanitizer.sanitize("password=hunter2 next"));
        assertEquals("Authorization: Bearer ****", LogSanitizer.sanitize("Authorization: Bearer abcdefghijklmnop"));
        assertEquals("{\"token\":\"****\"}", LogSanitizer.sanitize("{\"token\":\"abc123\"}"));
        assertTrue(LogSanitizer.sanitize(repeat('a', 5000)).endsWith("...[truncated]"));
    }

    @Test
    void safeDeserialization() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bytes);
        out.writeObject(new ArrayList<String>(Collections.singletonList("x")));
        out.close();
        assertThrows(InvalidClassException.class,
                () -> new SafeObjectInputStream(new ByteArrayInputStream(bytes.toByteArray())).readObject());
        Object ok = new SafeObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()), "java.util.ArrayList").readObject();
        assertEquals(Collections.singletonList("x"), ok);
    }

    @Test
    void requestInspector() {
        HttpRequestInspector inspector = new HttpRequestInspector();
        Map<String, String[]> params = new HashMap<String, String[]>();
        params.put("id", new String[] {"1;SELECT pg_sleep(5)--"});
        Map<String, String> headers = Collections.singletonMap("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        HttpRequestInspector.Report r = inspector.inspect("/api/orders", params, headers);
        assertTrue(r.isMalicious());
        assertTrue(r.summary().startsWith("param:id="), r.summary());
        assertFalse(r.summary().contains("pg_sleep(5)"), "report must not echo input");

        params.put("id", new String[] {"42"});
        assertFalse(inspector.inspect("/api/orders/42", params, headers).isSuspicious());
        assertTrue(inspector.inspect("/files/..%2f..%2fetc/passwd", null, null).isMalicious());
        assertTrue(inspector.inspect("/", null, Collections.singletonMap("user-agent", "${jndi:ldap://x/a}")).isMalicious());
    }

    @Test
    void safeErrorsNeverLeakDetails() {
        java.util.logging.Logger logger = java.util.logging.Logger.getAnonymousLogger();
        logger.setUseParentHandlers(false);
        final StringBuilder logged = new StringBuilder();
        logger.addHandler(new java.util.logging.Handler() {
            @Override public void publish(java.util.logging.LogRecord r) { logged.append(r.getMessage()); }
            @Override public void flush() { }
            @Override public void close() { }
        });
        String id = io.github.wahindra.secure.errors.SafeErrors.log(logger,
                new IllegalStateException("SELECT * FROM secret_table\nforged line"), "checkout password=hunter2");
        String body = io.github.wahindra.secure.errors.SafeErrors.publicBody(id);
        assertTrue(body.contains(id));
        assertFalse(body.contains("secret_table"));
        assertTrue(logged.toString().contains("incident=" + id));
        assertTrue(logged.toString().contains("secret_table"), "detail stays server-side");
        assertFalse(logged.toString().contains("\n"), "log forging neutralized");
        assertFalse(logged.toString().contains("hunter2"), "secrets masked");
        assertEquals("{\"error\":\"An unexpected error occurred.\",\"incidentId\":\"abc\"}",
                io.github.wahindra.secure.errors.SafeErrors.publicBody("a\"b<c"));
    }

    @Test
    void securityHeaders() {
        Map<String, String> h = io.github.wahindra.secure.web.SecurityHeaders.builder()
                .noStore().hstsPreload().set("X-Frame-Options", null).contentSecurityPolicy("default-src 'none'").build().asMap();
        assertEquals("nosniff", h.get("X-Content-Type-Options"));
        assertEquals("no-store", h.get("Cache-Control"));
        assertEquals("default-src 'none'", h.get("Content-Security-Policy"));
        assertTrue(h.get("Strict-Transport-Security").contains("preload"));
        assertFalse(h.containsKey("X-Frame-Options"));
        assertTrue(io.github.wahindra.secure.web.SecurityHeaders.defaults().asMap().get("Content-Security-Policy")
                .contains("frame-ancestors 'none'"));
    }

    @Test
    void webhookSignature() {
        HmacSigner s = new HmacSigner(KEY);
        byte[] body = "{\"event\":\"paid\"}".getBytes(StandardCharsets.UTF_8);
        // Expected value computed independently: printf '%s' '{"event":"paid"}' | openssl dgst -sha256 -hmac <key>
        String hex = CrossLanguage.HMAC_HEX_PAID;
        assertTrue(s.verifyHex(body, "sha256=" + hex));
        assertTrue(s.verifyHex(body, hex.toUpperCase(java.util.Locale.ROOT)));
        assertFalse(s.verifyHex("{\"event\":\"refund\"}".getBytes(StandardCharsets.UTF_8), "sha256=" + hex));
        assertFalse(s.verifyHex(body, null));
    }

    @Test
    void deserializationRejectsProxiesAndAllowsPackages() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bytes);
        out.writeObject(new java.util.Date(0));
        out.writeObject(new int[] {1, 2});
        out.writeObject(new String[] {"a"});
        out.close();
        SafeObjectInputStream in = new SafeObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()));
        assertEquals(new java.util.Date(0), in.readObject());
        assertEquals(2, ((int[]) in.readObject()).length);
        assertEquals("a", ((String[]) in.readObject())[0]);

        ByteArrayOutputStream proxyBytes = new ByteArrayOutputStream();
        ObjectOutputStream pout = new ObjectOutputStream(proxyBytes);
        pout.writeObject(java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {Runnable.class, java.io.Serializable.class}, new SerializableHandler()));
        pout.close();
        assertThrows(InvalidClassException.class,
                () -> new SafeObjectInputStream(new ByteArrayInputStream(proxyBytes.toByteArray()), "java.").readObject());
    }

    private static final class SerializableHandler implements java.lang.reflect.InvocationHandler, java.io.Serializable {
        private static final long serialVersionUID = 1L;

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) {
            return null;
        }
    }

    private static String repeat(char c, int n) {
        char[] a = new char[n];
        Arrays.fill(a, c);
        return new String(a);
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
