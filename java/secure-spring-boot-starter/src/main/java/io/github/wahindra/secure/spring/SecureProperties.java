package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.audit.AuditFormat;
import io.github.wahindra.secure.audit.SyslogAuditSink;
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
 *   audit:
 *     file:
 *       path: /var/log/orders/security-audit.jsonl
 *       hash-chain: true
 *     syslog:
 *       host: siem.example.com
 *       protocol: tls
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
    private final Audit audit = new Audit();

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
    /**
     * Audit log of security events, logins and application actions ({@code Auditor}). Turned on by
     * setting a file path or a syslog host (or by an {@code AuditSink} bean of your own).
     */
    public static class Audit {
        /** Records held while the destinations catch up; beyond this they are dropped and counted. */
        private int queueCapacity = 10_000;
        /** Also record failed bearer-token / login authentication reported by Spring Security. */
        private boolean authenticationFailures = true;
        private final File file = new File();
        private final Syslog syslog = new Syslog();

        public int getQueueCapacity() { return queueCapacity; }
        public void setQueueCapacity(int v) { queueCapacity = v; }
        public boolean isAuthenticationFailures() { return authenticationFailures; }
        public void setAuthenticationFailures(boolean v) { authenticationFailures = v; }
        public File getFile() { return file; }
        public Syslog getSyslog() { return syslog; }

        public static class File {
            /** Where to write, e.g. {@code /var/log/orders/security-audit.jsonl}. Empty: no file. */
            private String path;
            /** {@code json}, {@code ecs} or {@code cef}. */
            private AuditFormat format = AuditFormat.JSON;
            /** Rotate when the file would grow past this many bytes (0: never). */
            private long maxBytes = 10L * 1024 * 1024;
            /** Rotated files to keep. */
            private int maxFiles = 10;
            /** Add a hash chain to every line; check it with {@code secure audit verify}. */
            private boolean hashChain;
            /** HMAC key for the chain (at least 16 characters; implies hash-chain). Keep it in a secret store. */
            private String hmacKey;

            public String getPath() { return path; }
            public void setPath(String v) { path = v; }
            public AuditFormat getFormat() { return format; }
            public void setFormat(AuditFormat v) { format = v; }
            public long getMaxBytes() { return maxBytes; }
            public void setMaxBytes(long v) { maxBytes = v; }
            public int getMaxFiles() { return maxFiles; }
            public void setMaxFiles(int v) { maxFiles = v; }
            public boolean isHashChain() { return hashChain; }
            public void setHashChain(boolean v) { hashChain = v; }
            public String getHmacKey() { return hmacKey; }
            public void setHmacKey(String v) { hmacKey = v; }
        }

        public static class Syslog {
            /** SIEM / syslog collector host. Empty: no syslog. */
            private String host;
            /** Default: 514 for UDP and TCP, 6514 for TLS. */
            private Integer port;
            /** {@code udp}, {@code tcp} or {@code tls}. Use TLS across networks. */
            private SyslogAuditSink.Protocol protocol = SyslogAuditSink.Protocol.UDP;
            /** {@code cef} (ArcSight, QRadar, Sentinel), {@code ecs} or {@code json}. */
            private AuditFormat format = AuditFormat.CEF;
            /** RFC 5424 APP-NAME. Default: spring.application.name, else "secure". */
            private String appName;
            /** Syslog facility 0..23 (13: log audit). */
            private int facility = 13;

            public String getHost() { return host; }
            public void setHost(String v) { host = v; }
            public Integer getPort() { return port; }
            public void setPort(Integer v) { port = v; }
            public SyslogAuditSink.Protocol getProtocol() { return protocol; }
            public void setProtocol(SyslogAuditSink.Protocol v) { protocol = v; }
            public AuditFormat getFormat() { return format; }
            public void setFormat(AuditFormat v) { format = v; }
            public String getAppName() { return appName; }
            public void setAppName(String v) { appName = v; }
            public int getFacility() { return facility; }
            public void setFacility(int v) { facility = v; }
        }
    }

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
    public Audit getAudit() { return audit; }
}
