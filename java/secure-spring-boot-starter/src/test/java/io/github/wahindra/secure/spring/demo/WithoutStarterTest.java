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
}
