package io.github.wahindra.secure.spring.demo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.wahindra.secure.access.AccessGuard;
import io.github.wahindra.secure.access.SecurityPrincipal;
import io.github.wahindra.secure.spring.CurrentUser;
import io.github.wahindra.secure.web.SafeRedirect;
import io.github.wahindra.secure.web.SecurityEvent;
import io.github.wahindra.secure.web.SecurityEventListener;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A small API secured the usual way: Spring Security as a JWT resource server (Keycloak-shaped
 * tokens) plus secure-spring-boot-starter. Some endpoints are deliberately vulnerable, so the
 * end-to-end tests can show what the starter blocks and what the developer tools detect.
 */
@SpringBootApplication
public class DemoApplication {

    /** Test identity provider: an RSA key pair and Keycloak-style access tokens. */
    public static final class Tokens {
        private static final KeyPair KEYS;

        static {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(2048);
                KEYS = g.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        public static String issue(String subject, String... realmRoles) {
            try {
                JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .subject(subject)
                        .issuer("https://idp.test/realms/shop")
                        .claim("preferred_username", subject)
                        .claim("realm_access", Map.of("roles", List.of(realmRoles)))
                        .claim("resource_access", Map.of("orders-api", Map.of("roles", List.of("order-reader"))))
                        .claim("scope", "openid profile")
                        .issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 600_000))
                        .build();
                SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
                jwt.sign(new RSASSASigner(KEYS.getPrivate()));
                return jwt.serialize();
            } catch (JOSEException e) {
                throw new IllegalStateException(e);
            }
        }

        static RSAPublicKey publicKey() {
            return (RSAPublicKey) KEYS.getPublic();
        }
    }

    /** Collects events, standing in for a SIEM or Slack listener. */
    public static final List<SecurityEvent> EVENTS = new CopyOnWriteArrayList<>();

    @Bean
    SecurityEventListener collectingListener() {
        return EVENTS::add;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // secure-scan:ignore SPRING_CSRF_DISABLED -- stateless JWT API: no cookies, so no CSRF
        http.csrf(c -> c.disable())
                .authorizeHttpRequests(a -> a.requestMatchers("/api/search", "/go", "/error").permitAll().anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(Tokens.publicKey()).build();
    }

    public record Order(long id, String ownerId, String email) {
    }

    @RestController
    static class Api {
        private final Map<Long, Order> orders = Map.of(
                1L, new Order(1, "alice", "alice@shop.test"),
                2L, new Order(2, "bob", "bob@shop.test"));

        /** Vulnerable on purpose: reflects the query unencoded (XSS). The starter must block attacks. */
        @GetMapping("/api/search")
        String search(@RequestParam String q) {
            return "<p>Results for " + q + "</p>";
        }

        /** Same, with a JSON body. */
        @PostMapping("/api/search")
        String searchJson(@RequestBody Map<String, Object> body) {
            return "<p>Results for " + body.get("q") + "</p>";
        }

        /** Correct: identity from the token, ownership checked. */
        @GetMapping("/api/orders/{id}")
        Order order(@PathVariable long id, @CurrentUser SecurityPrincipal user) {
            Order order = orders.get(id);
            if (order == null) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
            AccessGuard.requireOwnerOrRole(user, order.ownerId(), "admin");
            return order;
        }

        /** Broken on purpose: logged-in check only (IDOR). `secure idor` must catch it. */
        @GetMapping("/api/vuln/orders/{id}")
        Order vulnerableOrder(@PathVariable long id) {
            return orders.get(id);
        }

        @GetMapping("/api/me")
        Map<String, Object> me(@CurrentUser SecurityPrincipal user) {
            return Map.of("id", user.getId(), "roles", user.getRoles());
        }

        @GetMapping("/go")
        ResponseEntity<Void> go(@RequestParam String next) {
            return ResponseEntity.status(302).header("Location", SafeRedirect.target(next, "/", "accounts.shop.test")).build();
        }
    }
}
