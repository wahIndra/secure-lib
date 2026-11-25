package io.github.wahindra.secure.spring.demo;

import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.AttackProbe;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Control experiment: the same app with the starter switched off. The probe must now find the
 * XSS in /api/search, which shows that the end-to-end test passes because of the starter, and
 * that the probe really detects vulnerabilities.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "secure.enabled=false")
class WithoutStarterTest {

    @Autowired
    private Environment env;

    @Test
    void probeFindsTheReflectedXss() throws Exception {
        String base = "http://127.0.0.1:" + env.getProperty("local.server.port");
        List<AttackProbe.Result> results = AttackProbe.run(new AttackProbe.Target(base + "/api/search?q=FUZZ").only("xss"), null);
        assertTrue(results.stream().anyMatch(r -> r.getSeverity() == Severity.HIGH), "XSS must be found without the starter");
    }

    /** Control for the UTF-16 test: Spring really decodes such a body, so the attack is real. */
    @Test
    void springDecodesUtf16JsonBodies() throws Exception {
        String base = "http://127.0.0.1:" + env.getProperty("local.server.port");
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/api/search"))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray("{\"q\":\"<b>x</b>\"}".getBytes(java.nio.charset.StandardCharsets.UTF_16LE)))
                .build();
        java.net.http.HttpResponse<String> r = java.net.http.HttpClient.newHttpClient().send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
        assertTrue(r.statusCode() == 200 && r.body().contains("<b>x</b>"), "Jackson must decode UTF-16: " + r.statusCode() + " " + r.body());
    }
}
