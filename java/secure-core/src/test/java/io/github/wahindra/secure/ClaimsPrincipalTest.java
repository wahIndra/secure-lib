package io.github.wahindra.secure;

import io.github.wahindra.secure.access.AccessDeniedException;
import io.github.wahindra.secure.access.AccessGuard;
import io.github.wahindra.secure.access.ClaimMapping;
import io.github.wahindra.secure.access.ClaimsPrincipal;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Claim shapes as issued by each provider (decoded, already-verified access tokens). */
class ClaimsPrincipalTest {

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new HashMap<String, Object>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private static final Map<String, Object> KEYCLOAK = map(
            "sub", "f1c2a8e0-alice",
            "preferred_username", "alice",
            "realm_access", map("roles", Arrays.asList("user", "offline_access")),
            "resource_access", map(
                    "orders-api", map("roles", Arrays.asList("order-reader")),
                    "account", map("roles", Arrays.asList("manage-account"))),
            "scope", "openid profile email");

    @Test
    void keycloakRealmAndClientRoles() {
        ClaimsPrincipal p = ClaimsPrincipal.fromVerifiedClaims(KEYCLOAK, ClaimMapping.keycloak("orders-api"));
        assertEquals("f1c2a8e0-alice", p.getId());
        assertEquals(new LinkedHashSet<String>(Arrays.asList("user", "offline_access", "order-reader")), p.getRoles());
        assertTrue(p.getPermissions().contains("email"));
        assertEquals("alice", p.getClaim("preferred_username"));
        assertNull(p.getTenantId());
        // Roles of other clients are not granted.
        assertTrue(!p.getRoles().contains("manage-account"));
        // Realm-only preset.
        assertEquals(new LinkedHashSet<String>(Arrays.asList("user", "offline_access")),
                ClaimsPrincipal.fromVerifiedClaims(KEYCLOAK, ClaimMapping.keycloak()).getRoles());
    }

    @Test
    void entraIdUsesObjectIdAndTenant() {
        ClaimsPrincipal p = ClaimsPrincipal.fromVerifiedClaims(map(
                "sub", "pairwise-per-app", "oid", "7f3c-object-id", "tid", "contoso-tenant",
                "roles", Arrays.asList("Orders.Admin"), "scp", "Orders.Read User.Read"), ClaimMapping.entraId());
        assertEquals("7f3c-object-id", p.getId());
        assertEquals("contoso-tenant", p.getTenantId());
        assertTrue(p.getRoles().contains("Orders.Admin"));
        assertTrue(p.getPermissions().contains("Orders.Read"));
    }

    @Test
    void auth0NamespacedClaimOktaCognitoAndStandard() {
        ClaimsPrincipal auth0 = ClaimsPrincipal.fromVerifiedClaims(map(
                "sub", "auth0|123", "https://example.com/roles", Arrays.asList("admin"),
                "permissions", Arrays.asList("read:orders")), ClaimMapping.auth0("https://example.com/roles"));
        assertTrue(auth0.getRoles().contains("admin"));
        assertTrue(auth0.getPermissions().contains("read:orders"));

        assertTrue(ClaimsPrincipal.fromVerifiedClaims(map("sub", "00u1", "groups", Arrays.asList("Everyone", "Admins"),
                "scp", Arrays.asList("orders.read")), ClaimMapping.okta()).getRoles().contains("Admins"));

        ClaimsPrincipal cognito = ClaimsPrincipal.fromVerifiedClaims(map("sub", "c0g", "cognito:groups", new String[] {"admins"},
                "scope", "orders/read"), ClaimMapping.cognito());
        assertTrue(cognito.getRoles().contains("admins"));
        assertTrue(cognito.getPermissions().contains("orders/read"));

        ClaimsPrincipal std = ClaimsPrincipal.fromVerifiedClaims(map("sub", 42, "roles", "a, b"), ClaimMapping.standard());
        assertEquals("42", std.getId());
        assertEquals(new LinkedHashSet<String>(Arrays.asList("a", "b")), std.getRoles());
    }

    @Test
    void customMappingAndTenantViaBuilder() {
        ClaimMapping m = ClaimMapping.keycloak("orders-api").toBuilder().tenantClaim("org.id").build();
        Map<String, Object> claims = new HashMap<String, Object>(KEYCLOAK);
        claims.put("org", map("id", "acme"));
        assertEquals("acme", ClaimsPrincipal.fromVerifiedClaims(claims, m).getTenantId());
    }

    @Test
    void missingSubjectIsUnauthenticated() {
        AccessDeniedException e = assertThrows(AccessDeniedException.class,
                () -> ClaimsPrincipal.fromVerifiedClaims(map("preferred_username", "alice"), ClaimMapping.keycloak()));
        assertTrue(e.isUnauthenticated());
        assertThrows(AccessDeniedException.class,
                () -> ClaimsPrincipal.fromVerifiedClaims(Collections.<String, Object>emptyMap(), ClaimMapping.standard()));
        assertThrows(AccessDeniedException.class, () -> ClaimsPrincipal.fromVerifiedClaims(null, ClaimMapping.standard()));
    }

    /** The IDOR fix end to end: identity from the token, ownership checked on the object. */
    @Test
    void ownershipCheckWithTokenIdentity() {
        ClaimsPrincipal alice = ClaimsPrincipal.fromVerifiedClaims(KEYCLOAK, ClaimMapping.keycloak("orders-api"));
        assertDoesNotThrow(() -> AccessGuard.requireOwner(alice, "f1c2a8e0-alice"));
        assertThrows(AccessDeniedException.class, () -> AccessGuard.requireOwner(alice, "b0b-other-user"));
        assertThrows(AccessDeniedException.class, () -> AccessGuard.requireOwnerOrRole(alice, "b0b-other-user", "admin"));
        ClaimsPrincipal admin = ClaimsPrincipal.fromVerifiedClaims(map("sub", "root",
                "realm_access", map("roles", Arrays.asList("admin"))), ClaimMapping.keycloak());
        assertDoesNotThrow(() -> AccessGuard.requireOwnerOrRole(admin, "b0b-other-user", "admin"));
    }
}
