package io.github.wahindra.secure.access;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The caller, built from the claims of an <b>already verified</b> access token, so that identity
 * comes from the identity provider and never from the request. Works with any OIDC / JWT issuer
 * through a {@link ClaimMapping} (presets for Keycloak, Auth0, Entra ID, Okta, Cognito).
 *
 * <p>This class does not verify tokens. Verify signature, issuer, audience and expiry first with
 * your framework (Spring Security resource server, Quarkus OIDC, a JOSE library), then pass the
 * resulting claims here:
 *
 * <pre>
 * &#64;GetMapping("/api/orders/{id}")
 * Order order(&#64;PathVariable long id, &#64;AuthenticationPrincipal Jwt jwt) {
 *     SecurityPrincipal user = ClaimsPrincipal.fromVerifiedClaims(jwt.getClaims(), ClaimMapping.keycloak("orders-api"));
 *     Order order = repo.findById(id).orElseThrow(NotFound::new);
 *     AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "ADMIN");
 *     return order;
 * }
 * </pre>
 *
 * <p>If one backend accepts tokens from several issuers, user ids can collide across them. Use a
 * separate mapping per issuer, or store owner ids as {@code iss + "|" + sub}.
 */
public final class ClaimsPrincipal implements SecurityPrincipal {

    private final String id;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final String tenantId;
    private final Map<String, Object> claims;

    private ClaimsPrincipal(String id, Set<String> roles, Set<String> permissions, String tenantId, Map<String, Object> claims) {
        this.id = id;
        this.roles = Collections.unmodifiableSet(roles);
        this.permissions = Collections.unmodifiableSet(permissions);
        this.tenantId = tenantId;
        this.claims = Collections.unmodifiableMap(claims);
    }

    /**
     * @param claims  claims of a token whose signature, issuer, audience and expiry were verified
     * @param mapping where this issuer puts id, roles, permissions and tenant
     * @throws AccessDeniedException (unauthenticated) if the id claim is missing or empty
     */
    public static ClaimsPrincipal fromVerifiedClaims(Map<String, ?> claims, ClaimMapping mapping) {
        if (claims == null || mapping == null) {
            throw new AccessDeniedException("no verified token", true);
        }
        Object rawId = claim(claims, mapping.getIdClaim());
        String id = rawId instanceof String || rawId instanceof Number ? String.valueOf(rawId).trim() : "";
        if (id.isEmpty()) {
            throw new AccessDeniedException("token has no '" + mapping.getIdClaim() + "' claim", true);
        }
        Set<String> roles = new LinkedHashSet<String>();
        for (String path : mapping.getRoleClaims()) {
            collect(claim(claims, path), roles, false);
        }
        Set<String> permissions = new LinkedHashSet<String>();
        for (String path : mapping.getPermissionClaims()) {
            collect(claim(claims, path), permissions, true);
        }
        String tenant = null;
        if (mapping.getTenantClaim() != null) {
            Object t = claim(claims, mapping.getTenantClaim());
            tenant = t instanceof String || t instanceof Number ? String.valueOf(t) : null;
        }
        return new ClaimsPrincipal(id, roles, permissions, tenant, new LinkedHashMap<String, Object>(claims));
    }

    @Override public String getId() { return id; }
    @Override public Set<String> getRoles() { return roles; }
    @Override public Set<String> getPermissions() { return permissions; }
    @Override public String getTenantId() { return tenantId; }

    /** Any other claim, e.g. {@code email} or {@code preferred_username}, by name or dot path. */
    public Object getClaim(String path) {
        return claim(claims, path);
    }

    /**
     * Looks up a claim: the whole path as a top-level name first (for names that contain dots,
     * such as {@code https://example.com/roles}), then as a dot path through nested objects.
     */
    static Object claim(Map<String, ?> claims, String path) {
        if (path == null || claims == null) {
            return null;
        }
        if (claims.containsKey(path)) {
            return claims.get(path);
        }
        Object current = claims;
        for (String part : path.split("\\.")) {
            if (!(current instanceof Map)) {
                return null;
            }
            current = ((Map<?, ?>) current).get(part);
        }
        return current;
    }

    /**
     * Each element of an array or collection is one value, taken whole: a group named "Team admin"
     * must never grant the role "admin". Only a claim that is a single string is split, on spaces,
     * and only for permission claims, because OAuth {@code scope} is space-delimited. A single
     * string in a role claim is one role. Non-string elements are ignored.
     */
    private static void collect(Object value, Set<String> out, boolean spaceDelimitedString) {
        if (value instanceof String) {
            String s = ((String) value).trim();
            if (spaceDelimitedString) {
                for (String part : s.split("\\s+")) {
                    if (!part.isEmpty()) {
                        out.add(part);
                    }
                }
            } else if (!s.isEmpty()) {
                out.add(s);
            }
        } else if (value instanceof Collection) {
            for (Object v : (Collection<?>) value) {
                addElement(v, out);
            }
        } else if (value != null && value.getClass().isArray()) {
            for (int i = 0; i < Array.getLength(value); i++) {
                addElement(Array.get(value, i), out);
            }
        }
    }

    private static void addElement(Object v, Set<String> out) {
        if (v instanceof String && !((String) v).trim().isEmpty()) {
            out.add(((String) v).trim());
        }
    }

    @Override
    public String toString() {
        return "ClaimsPrincipal{id=" + id + ", roles=" + roles + ", tenant=" + tenantId + "}";
    }
}
