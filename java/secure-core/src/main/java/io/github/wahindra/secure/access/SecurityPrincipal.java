package io.github.wahindra.secure.access;

import java.util.Collections;
import java.util.Set;

/** The authenticated caller. Adapt your framework's user object to this interface. */
public interface SecurityPrincipal {

    String getId();

    Set<String> getRoles();

    default Set<String> getPermissions() {
        return Collections.emptySet();
    }

    /** Tenant or organisation the caller belongs to; {@code null} for single-tenant apps. */
    default String getTenantId() {
        return null;
    }
}
