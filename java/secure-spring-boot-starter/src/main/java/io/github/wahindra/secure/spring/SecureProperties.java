package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.web.HttpRequestInspector;
import io.github.wahindra.secure.web.SecurityFilterEngine;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.Ordered;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * {@code secure.*} settings. Every value has a safe default, so adding the starter is enough;
 * start with {@code secure.mode=monitor} in production to tune false positives first.
 *
 * <pre>
 * secure:
 *   mode: monitor
 *   identity:
 *     provider: keycloak
 *     client-id: orders-api
 *   cors:
 *     allowed-origins: https://app.example.com
 *   rate-limit:
 *     enabled: true
 *     requests-per-minute: 300
 * </pre>
 */
@ConfigurationProperties(prefix = "secure")
public class SecureProperties {

    /** Turn the whole starter off. */
    private boolean enabled = true;
    /** {@code block} rejects malicious requests with 400; {@code monitor} only reports them. */
    private SecurityFilterEngine.Mode mode = SecurityFilterEngine.Mode.BLOCK;
    /** Add the recommended security headers (CSP, HSTS, nosniff, frame-ancestors...). */
    private boolean securityHeaders = true;
    /** Let requests through when inspection itself fails. Default: reject. */
    private boolean failOpen;
    /** Position in the servlet filter chain. Default runs before Spring Security (-100). */
    private int filterOrder = Ordered.HIGHEST_PRECEDENCE + 10;
    /** URL patterns the filter applies to. */
    private List<String> urlPatterns = new ArrayList<String>(Arrays.asList("/*"));

    private final Inspection inspection = new Inspection();
    private final RateLimit rateLimit = new RateLimit();
    private final Cors cors = new Cors();
    private final Identity identity = new Identity();

    public static class Inspection {
        /** Inspect JSON request bodies (read once, then replayed to the application). */
        private boolean jsonBody = true;
        /** Largest JSON body inspected; larger ones are rejected in block mode. */
        private int maxBodyBytes = SecurityFilterEngine.DEFAULT_MAX_BODY_BYTES;
        private int maxValues = HttpRequestInspector.DEFAULT_MAX_VALUES;
        private int maxInspectedChars = HttpRequestInspector.DEFAULT_MAX_INSPECTED_CHARS;
        private int maxJsonDepth = HttpRequestInspector.DEFAULT_MAX_JSON_DEPTH;
        /** Request headers to inspect. */
        private List<String> headers = new ArrayList<String>(HttpRequestInspector.DEFAULT_HEADERS);

        public boolean isJsonBody() { return jsonBody; }
        public void setJsonBody(boolean v) { jsonBody = v; }
        public int getMaxBodyBytes() { return maxBodyBytes; }
        public void setMaxBodyBytes(int v) { maxBodyBytes = v; }
        public int getMaxValues() { return maxValues; }
        public void setMaxValues(int v) { maxValues = v; }
        public int getMaxInspectedChars() { return maxInspectedChars; }
        public void setMaxInspectedChars(int v) { maxInspectedChars = v; }
        public int getMaxJsonDepth() { return maxJsonDepth; }
        public void setMaxJsonDepth(int v) { maxJsonDepth = v; }
        public List<String> getHeaders() { return headers; }
        public void setHeaders(List<String> v) { headers = v; }
    }

    public static class RateLimit {
        private boolean enabled;
        /** Requests per minute per client address (burst up to the same number). */
        private int requestsPerMinute = 300;
        /** Most client addresses tracked at once; the least recently seen is forgotten first. */
        private int maxKeys = 100_000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { enabled = v; }
        public int getRequestsPerMinute() { return requestsPerMinute; }
        public void setRequestsPerMinute(int v) { requestsPerMinute = v; }
        public int getMaxKeys() { return maxKeys; }
        public void setMaxKeys(int v) { maxKeys = v; }
    }

    public static class Cors {
        /** Exact origins or {@code https://*.example.com}. Empty: no CORS handling. */
        private List<String> allowedOrigins = new ArrayList<String>();
        private List<String> allowedMethods = new ArrayList<String>(Arrays.asList("GET", "HEAD", "POST"));
        private List<String> allowedHeaders = new ArrayList<String>(Arrays.asList("Content-Type", "Authorization"));
        private List<String> exposedHeaders = new ArrayList<String>();
        private boolean allowCredentials;
        private long maxAgeSeconds = 600;

        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> v) { allowedOrigins = v; }
        public List<String> getAllowedMethods() { return allowedMethods; }
        public void setAllowedMethods(List<String> v) { allowedMethods = v; }
        public List<String> getAllowedHeaders() { return allowedHeaders; }
        public void setAllowedHeaders(List<String> v) { allowedHeaders = v; }
        public List<String> getExposedHeaders() { return exposedHeaders; }
        public void setExposedHeaders(List<String> v) { exposedHeaders = v; }
        public boolean isAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(boolean v) { allowCredentials = v; }
        public long getMaxAgeSeconds() { return maxAgeSeconds; }
        public void setMaxAgeSeconds(long v) { maxAgeSeconds = v; }
    }

    /** How {@code @CurrentUser} reads a verified token: which issuer and where it keeps roles. */
    public static class Identity {
        public enum Provider { STANDARD, KEYCLOAK, AUTH0, ENTRA_ID, OKTA, COGNITO }

        private Provider provider = Provider.STANDARD;
        /** Keycloak: client whose roles are granted ({@code resource_access.<client-id>.roles}). */
        private String clientId;
        /** Auth0: the namespaced roles claim, e.g. {@code https://example.com/roles}. */
        private String rolesClaim;
        /** Overrides the provider's user id claim. */
        private String idClaim;
        /** Claim holding the tenant id, for multi-tenant apps. */
        private String tenantClaim;

        public Provider getProvider() { return provider; }
        public void setProvider(Provider v) { provider = v; }
        public String getClientId() { return clientId; }
        public void setClientId(String v) { clientId = v; }
        public String getRolesClaim() { return rolesClaim; }
        public void setRolesClaim(String v) { rolesClaim = v; }
        public String getIdClaim() { return idClaim; }
        public void setIdClaim(String v) { idClaim = v; }
        public String getTenantClaim() { return tenantClaim; }
        public void setTenantClaim(String v) { tenantClaim = v; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean v) { enabled = v; }
    public SecurityFilterEngine.Mode getMode() { return mode; }
    public void setMode(SecurityFilterEngine.Mode v) { mode = v; }
    public boolean isSecurityHeaders() { return securityHeaders; }
    public void setSecurityHeaders(boolean v) { securityHeaders = v; }
    public boolean isFailOpen() { return failOpen; }
    public void setFailOpen(boolean v) { failOpen = v; }
    public int getFilterOrder() { return filterOrder; }
    public void setFilterOrder(int v) { filterOrder = v; }
    public List<String> getUrlPatterns() { return urlPatterns; }
    public void setUrlPatterns(List<String> v) { urlPatterns = v; }
    public Inspection getInspection() { return inspection; }
    public RateLimit getRateLimit() { return rateLimit; }
    public Cors getCors() { return cors; }
    public Identity getIdentity() { return identity; }
}
