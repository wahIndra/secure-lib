package io.github.wahindra.secure.access;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class SimplePrincipal implements SecurityPrincipal {

    private final String id;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final String tenantId;

    private SimplePrincipal(Builder b) {
        this.id = b.id;
        this.roles = Collections.unmodifiableSet(new LinkedHashSet<String>(b.roles));
        this.permissions = Collections.unmodifiableSet(new LinkedHashSet<String>(b.permissions));
        this.tenantId = b.tenantId;
    }

    public static Builder builder(String id) {
        return new Builder(id);
    }

    @Override public String getId() { return id; }
    @Override public Set<String> getRoles() { return roles; }
    @Override public Set<String> getPermissions() { return permissions; }
    @Override public String getTenantId() { return tenantId; }

    public static final class Builder {
        private final String id;
        private final Set<String> roles = new LinkedHashSet<String>();
        private final Set<String> permissions = new LinkedHashSet<String>();
        private String tenantId;

        private Builder(String id) {
            this.id = id;
        }

        public Builder roles(String... values) {
            roles.addAll(Arrays.asList(values));
            return this;
        }

        public Builder permissions(String... values) {
            permissions.addAll(Arrays.asList(values));
            return this;
        }

        public Builder tenant(String value) {
            tenantId = value;
            return this;
        }

        public SimplePrincipal build() {
            return new SimplePrincipal(this);
        }
    }
}
