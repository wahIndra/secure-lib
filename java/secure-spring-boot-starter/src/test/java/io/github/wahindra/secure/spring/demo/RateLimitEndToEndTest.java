package io.github.wahindra.secure.spring.demo;

import io.github.wahindra.secure.web.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "secure.rate-limit.enabled=true",
        "secure.rate-limit.requests-per-minute=3",
})
class RateLimitEndToEndTest {

    @Autowired
    private Environment env;

    @Test
    void fourthRequestInAMinuteGets429() throws Exception {
        String url = "http://127.0.0.1:" + env.getProperty("local.server.port") + "/api/search?q=shoes";
        DemoApplication.EVENTS.clear();
        for (int i = 0; i < 3; i++) {
            assertEquals(200, Http.get(url).statusCode());
        }
        HttpResponse<String> limited = Http.get(url);
        assertEquals(429, limited.statusCode());
        assertTrue(limited.headers().firstValue("Retry-After").isPresent());
        assertEquals("0", limited.headers().firstValue("RateLimit-Remaining").orElse(null));
        assertTrue(DemoApplication.EVENTS.stream().anyMatch(e -> e.getType() == SecurityEvent.Type.RATE_LIMITED));
    }
}
