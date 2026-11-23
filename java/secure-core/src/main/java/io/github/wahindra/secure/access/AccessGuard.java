package io.github.wahindra.secure.access;

/**
 * Object-level checks to call in service code after loading a record. Route rules alone do
 * not stop IDOR: {@code GET /orders/1042} passes "authenticated" for every logged-in user.
 *
 * <pre>
 * Order order = repo.findById(id);
 * AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "ADMIN");
 * AccessGuard.requireSameTenant(user, order.getTenantId());
 * </pre>
 */
public final class AccessGuard {

    private AccessGuard() {
    }

    public static SecurityPrincipal requireAuthenticated(SecurityPrincipal principal) {
        if (principal == null || principal.getId() == null || principal.getId().isEmpty()) {
            throw new AccessDeniedException("authentication required", true);
        }
        return principal;
    }

    public static boolean hasAnyRole(SecurityPrincipal principal, String... roles) {
        if (principal == null || principal.getRoles() == null) {
            return false;
        }
        for (String role : roles) {
            if (principal.getRoles().contains(role)) {
                return true;
            }
        }
        return false;
    }

    public static void requireAnyRole(SecurityPrincipal principal, String... roles) {
        requireAuthenticated(principal);
        if (!hasAnyRole(principal, roles)) {
            throw new AccessDeniedException("missing required role");
        }
    }

    public static void requireAllPermissions(SecurityPrincipal principal, String... permissions) {
        requireAuthenticated(principal);
        for (String p : permissions) {
            if (principal.getPermissions() == null || !principal.getPermissions().contains(p)) {
                throw new AccessDeniedException("missing required permission");
            }
        }
    }

    public static boolean isOwner(SecurityPrincipal principal, String resourceOwnerId) {
        return principal != null && principal.getId() != null && resourceOwnerId != null
                && principal.getId().equals(resourceOwnerId);
    }

    /** IDOR protection: the resource must belong to the caller. A missing owner id is denied. */
    public static void requireOwner(SecurityPrincipal principal, String resourceOwnerId) {
        requireAuthenticated(principal);
        if (!isOwner(principal, resourceOwnerId)) {
            throw new AccessDeniedException("caller does not own resource");
        }
    }

    public static void requireOwnerOrRole(SecurityPrincipal principal, String resourceOwnerId, String... overrideRoles) {
        requireAuthenticated(principal);
        if (!isOwner(principal, resourceOwnerId) && !hasAnyRole(principal, overrideRoles)) {
            throw new AccessDeniedException("caller does not own resource");
        }
    }

    /** Multi-tenant isolation. Both tenant ids must be present and equal. */
    public static void requireSameTenant(SecurityPrincipal principal, String resourceTenantId) {
        requireAuthenticated(principal);
        String tenant = principal.getTenantId();
        if (tenant == null || resourceTenantId == null || !tenant.equals(resourceTenantId)) {
            throw new AccessDeniedException("cross-tenant access");
        }
    }

    /**
     * Mass-assignment / privilege escalation guard: rejects requests that try to set fields
     * the caller may not change (e.g. "role", "ownerId", "isAdmin").
     */
    public static void requireNoProtectedFields(java.util.Collection<String> submittedFields, String... protectedFields) {
        for (String f : protectedFields) {
            for (String s : submittedFields) {
                if (s != null && s.equalsIgnoreCase(f)) {
                    throw new AccessDeniedException("attempt to set protected field");
                }
            }
        }
    }
}
