package io.github.wahindra.secure.access;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Where an identity provider puts the user id, roles, permissions and tenant in its tokens.
 * Use a preset, or {@link #builder()} for any other OIDC / JWT issuer.
 *
 * <p>Claim paths are dot-separated ({@code realm_access.roles}). A claim whose name itself contains
 * dots or slashes, such as Auth0's {@code https://example.com/roles}, is matched as a whole name
 * first, so it can be given as-is.
 *
 * <pre>
 * ClaimMapping.keycloak("orders-api")                        // realm + client roles
 * ClaimMapping.entraId()                                     // Microsoft Entra ID (Azure AD)
 * ClaimMapping.keycloak("orders-api").toBuilder().tenantClaim("tenant_id").build()
 * </pre>
 */
public final class ClaimMapping {

    private final String idClaim;
    private final List<String> roleClaims;
    private final List<String> permissionClaims;
    private final String tenantClaim;

    private ClaimMapping(Builder b) {
        this.idClaim = b.idClaim;
        this.roleClaims = Collections.unmodifiableList(new ArrayList<String>(b.roleClaims));
        this.permissionClaims = Collections.unmodifiableList(new ArrayList<String>(b.permissionClaims));
        this.tenantClaim = b.tenantClaim;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Standard OIDC: {@code sub}; roles in {@code roles} or {@code groups}; {@code scope}/{@code scp}/{@code permissions}. */
    public static ClaimMapping standard() {
        return builder().build();
    }

    /** Keycloak realm roles only ({@code realm_access.roles}). */
    public static ClaimMapping keycloak() {
        return builder().roleClaims("realm_access.roles").permissionClaims("scope").build();
    }

    /** Keycloak realm roles plus the roles of one client ({@code resource_access.<clientId>.roles}). */
    public static ClaimMapping keycloak(String clientId) {
        require(clientId, "clientId");
        return builder().roleClaims("realm_access.roles", "resource_access." + clientId + ".roles")
                .permissionClaims("scope").build();
    }

    /**
     * Auth0: roles live in a namespaced custom claim that you add with an Auth0 Action, e.g.
     * {@code https://example.com/roles}; RBAC permissions in {@code permissions}.
     */
    public static ClaimMapping auth0(String rolesClaim) {
        require(rolesClaim, "rolesClaim");
        return builder().roleClaims(rolesClaim).permissionClaims("permissions", "scope").build();
    }

    /**
     * Microsoft Entra ID (Azure AD). The id is {@code oid}, the user's object id, which is the same
     * for every app. {@code sub} is different per application. App roles are in {@code roles},
     * delegated scopes in {@code scp}, and the directory id in {@code tid}.
     */
    public static ClaimMapping entraId() {
        return builder().idClaim("oid").roleClaims("roles").permissionClaims("scp").tenantClaim("tid").build();
    }

    /** Okta: groups in {@code groups} (add the groups claim to the authorization server), scopes in {@code scp}. */
    public static ClaimMapping okta() {
        return builder().roleClaims("groups").permissionClaims("scp").build();
    }

    /** AWS Cognito user pools: groups in {@code cognito:groups}, scopes in {@code scope}. */
    public static ClaimMapping cognito() {
        return builder().roleClaims("cognito:groups").permissionClaims("scope").build();
    }

    public Builder toBuilder() {
        Builder b = new Builder();
        b.idClaim = idClaim;
        b.roleClaims = new ArrayList<String>(roleClaims);
        b.permissionClaims = new ArrayList<String>(permissionClaims);
        b.tenantClaim = tenantClaim;
        return b;
    }

    public String getIdClaim() { return idClaim; }
    public List<String> getRoleClaims() { return roleClaims; }
    public List<String> getPermissionClaims() { return permissionClaims; }
    /** {@code null} when the application is single-tenant. */
    public String getTenantClaim() { return tenantClaim; }

    private static void require(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    public static final class Builder {
        private String idClaim = "sub";
        private List<String> roleClaims = new ArrayList<String>(Arrays.asList("roles", "groups"));
        private List<String> permissionClaims = new ArrayList<String>(Arrays.asList("scope", "scp", "permissions"));
        private String tenantClaim;

        private Builder() {
        }

        /** Claim holding the stable user id. Default {@code sub}. */
        public Builder idClaim(String claim) {
            require(claim, "idClaim");
            idClaim = claim;
            return this;
        }

        /** Replaces the role claims. An array gives one role per element (never split); a single string is one role. */
        public Builder roleClaims(String... claims) {
            roleClaims = new ArrayList<String>(Arrays.asList(claims));
            return this;
        }

        /** Replaces the permission / scope claims. An array gives one permission per element; a single string is split on spaces (OAuth scope). */
        public Builder permissionClaims(String... claims) {
            permissionClaims = new ArrayList<String>(Arrays.asList(claims));
            return this;
        }

        /** Claim holding the tenant / organisation id, or {@code null} for single-tenant apps. */
        public Builder tenantClaim(String claim) {
            tenantClaim = claim;
            return this;
        }

        public ClaimMapping build() {
            return new ClaimMapping(this);
        }
    }
}
