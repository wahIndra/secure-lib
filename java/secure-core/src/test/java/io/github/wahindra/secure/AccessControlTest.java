package io.github.wahindra.secure;

import io.github.wahindra.secure.access.AccessDeniedException;
import io.github.wahindra.secure.access.AccessGuard;
import io.github.wahindra.secure.access.RouteAccessPolicy;
import io.github.wahindra.secure.access.SecurityPrincipal;
import io.github.wahindra.secure.access.SimplePrincipal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessControlTest {

    private final SecurityPrincipal alice = SimplePrincipal.builder("alice").roles("USER").tenant("t1").build();
    private final SecurityPrincipal admin = SimplePrincipal.builder("root").roles("ADMIN").tenant("t1").build();

    private final RouteAccessPolicy policy = RouteAccessPolicy.builder()
            .permitAll("GET", "/public/**")
            .permitAll("POST", "/login")
            .hasAnyRole("*", "/admin/**", "ADMIN")
            .authenticated("*", "/api/**")
            .build();

    @Test
    void denyByDefault() {
        assertFalse(policy.evaluate("GET", "/internal/metrics", admin).isAllowed());
        assertNull(policy.evaluate("GET", "/internal/metrics", admin).getMatchedRule());
    }

    @Test
    void rulesApply() {
        assertTrue(policy.evaluate("GET", "/public/logo.png", null).isAllowed());
        assertFalse(policy.evaluate("DELETE", "/public/logo.png", null).isAllowed());
        assertTrue(policy.evaluate("GET", "/api/orders", alice).isAllowed());
        assertTrue(policy.evaluate("GET", "/api/orders", null).isUnauthenticated());
        assertFalse(policy.evaluate("GET", "/admin/users", alice).isAllowed());
        assertTrue(policy.evaluate("GET", "/admin/users", admin).isAllowed());
        assertTrue(policy.evaluate("GET", "/admin", admin).isAllowed());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/public/../admin/users", "/public/%2e%2e/admin/users", "//admin/users", "/ADMIN/users",
            "/Admin/users/", "/admin;jsessionid=x/users", "/public/..;/admin/users", "/%61dmin/users",
            "/public%2f..%2fadmin/users", "/public\\..\\admin/users", "/admin/users%00.png", "/public/%252e%252e/admin"
    })
    void bypassAttemptsDoNotReachAdmin(String path) {
        assertFalse(policy.evaluate("GET", path, alice).isAllowed(), path);
    }

    @Test
    void canonicalize() {
        assertEquals("/a/b", RouteAccessPolicy.canonicalize("//a///b/?x=1"));
        assertEquals("/", RouteAccessPolicy.canonicalize(""));
        assertNull(RouteAccessPolicy.canonicalize("/a/../b"));
    }

    @Test
    void ownershipAndTenant() {
        assertDoesNotThrow(() -> AccessGuard.requireOwner(alice, "alice"));
        assertThrows(AccessDeniedException.class, () -> AccessGuard.requireOwner(alice, "bob"));
        assertThrows(AccessDeniedException.class, () -> AccessGuard.requireOwner(alice, null));
        assertDoesNotThrow(() -> AccessGuard.requireOwnerOrRole(admin, "bob", "ADMIN"));
        assertThrows(AccessDeniedException.class, () -> AccessGuard.requireSameTenant(alice, "t2"));
        assertThrows(AccessDeniedException.class, () -> AccessGuard.requireSameTenant(alice, null));
        AccessDeniedException e = assertThrows(AccessDeniedException.class, () -> AccessGuard.requireAnyRole(null, "USER"));
        assertTrue(e.isUnauthenticated());
        assertThrows(AccessDeniedException.class,
                () -> AccessGuard.requireNoProtectedFields(Arrays.asList("name", "Role"), "role", "ownerId"));
    }
}
