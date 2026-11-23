package io.github.wahindra.secure;

import io.github.wahindra.secure.ssrf.UrlGuard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SsrfTest {

    /** Offline resolver: literal IPs parse locally, a few fake names map to fixed addresses. */
    private static final UrlGuard.HostResolver FAKE_DNS = host -> {
        if (host.equals("public.example")) {
            return new InetAddress[] {InetAddress.getByName("93.184.215.14")};
        }
        if (host.equals("rebind.example")) {
            return new InetAddress[] {InetAddress.getByName("93.184.215.14"), InetAddress.getByName("10.0.0.5")};
        }
        if (host.equals("metadata.example")) {
            return new InetAddress[] {InetAddress.getByName("169.254.169.254")};
        }
        if (host.matches("[0-9a-f:.]+")) {
            return new InetAddress[] {InetAddress.getByName(host)};
        }
        throw new UnknownHostException(host);
    };

    private final UrlGuard guard = UrlGuard.builder().resolver(FAKE_DNS).build();

    @Test
    void allowsPublic() {
        assertEquals(443, guard.validate("https://public.example/hook").getPort());
        assertTrue(guard.isAllowed("http://93.184.215.14/x"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://127.0.0.1/", "http://localhost.invalid/", "http://10.1.2.3/", "http://172.16.0.1/",
            "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/", "http://metadata.example/",
            "http://0.0.0.0/", "http://100.64.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
            "http://[fd00::1]/", "http://[fe80::1]/", "http://[64:ff9b::a00:1]/", "http://[2002:a00:1::]/",
            "http://rebind.example/", "file:///etc/passwd", "gopher://public.example/", "ftp://public.example/",
            "http://user:pass@public.example/", "http://public.example:8080/", "http://public.example\\@evil/",
            "http://public.example /", "javascript:alert(1)", "http:///nohost", "http://224.0.0.1/"
    })
    void blocks(String url) {
        assertThrows(UrlGuard.SsrfException.class, () -> guard.validate(url), url);
    }

    @Test
    void hostAllowlist() {
        UrlGuard g = UrlGuard.builder().resolver(FAKE_DNS).allowHosts("*.example").build();
        assertTrue(g.isAllowed("https://public.example/"));
        assertFalse(g.isAllowed("https://93.184.215.14/"));
        assertFalse(UrlGuard.builder().resolver(FAKE_DNS).allowHosts("*.example").build().isAllowed("https://example/"));
    }
}
