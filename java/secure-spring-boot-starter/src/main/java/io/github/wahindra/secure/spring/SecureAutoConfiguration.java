package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.access.ClaimMapping;
import io.github.wahindra.secure.audit.AuditLog;
import io.github.wahindra.secure.audit.AuditSink;
import io.github.wahindra.secure.audit.FileAuditSink;
import io.github.wahindra.secure.audit.SyslogAuditSink;
import io.github.wahindra.secure.servlet.jakarta.SecurityFilter;
import io.github.wahindra.secure.web.CorsPolicy;
import io.github.wahindra.secure.web.HttpRequestInspector;
import io.github.wahindra.secure.web.RateLimiter;
import io.github.wahindra.secure.web.SecurityEventListener;
import io.github.wahindra.secure.web.SecurityFilterEngine;
import io.github.wahindra.secure.web.SecurityHeaders;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * Adding {@code secure-spring-boot-starter} to a Spring Boot 3 or 4 servlet application registers:
 * the request filter (inspection, security headers, optional CORS and rate limit) before Spring
 * Security; {@link CurrentUser} injection; safe error responses for the library's exceptions; and
 * every {@link SecurityEventListener} bean as an event listener; and, when configured, the audit log
 * ({@code secure.audit.*}) with {@link Auditor}. Configure with {@code secure.*}.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "secure", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SecureProperties.class)
public class SecureAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ClaimMapping secureClaimMapping(SecureProperties props) {
        SecureProperties.Identity id = props.getIdentity();
        ClaimMapping base;
        switch (id.getProvider()) {
            case KEYCLOAK:
                base = id.getClientId() == null || id.getClientId().trim().isEmpty()
                        ? ClaimMapping.keycloak() : ClaimMapping.keycloak(id.getClientId());
                break;
            case AUTH0:
                if (id.getRolesClaim() == null) {
                    throw new IllegalStateException("secure.identity.roles-claim is required for provider auth0");
                }
                base = ClaimMapping.auth0(id.getRolesClaim());
                break;
            case ENTRA_ID:
                base = ClaimMapping.entraId();
                break;
            case OKTA:
                base = ClaimMapping.okta();
                break;
            case COGNITO:
                base = ClaimMapping.cognito();
                break;
            default:
                base = ClaimMapping.standard();
        }
        ClaimMapping.Builder b = base.toBuilder();
        if (id.getIdClaim() != null) {
            b.idClaim(id.getIdClaim());
        }
        if (id.getTenantClaim() != null) {
            b.tenantClaim(id.getTenantClaim());
        }
        if (id.getRolesClaim() != null && id.getProvider() != SecureProperties.Identity.Provider.AUTH0) {
            b.roleClaims(id.getRolesClaim());
        }
        return b.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterEngine secureFilterEngine(SecureProperties props, ObjectProvider<SecurityEventListener> listeners) {
        SecureProperties.Inspection in = props.getInspection();
        SecurityFilterEngine.Builder b = SecurityFilterEngine.builder()
                .mode(props.getMode())
                .failOpen(props.isFailOpen())
                .securityHeaders(props.isSecurityHeaders() ? SecurityHeaders.defaults() : null)
                .inspectJsonBody(in.isJsonBody())
                .maxBodyBytes(in.getMaxBodyBytes())
                .inspector(HttpRequestInspector.builder().headers(in.getHeaders()).maxValues(in.getMaxValues())
                        .maxInspectedChars(in.getMaxInspectedChars()).maxJsonDepth(in.getMaxJsonDepth()).build());
        if (props.getRateLimit().isEnabled()) {
            SecureProperties.RateLimit rl = props.getRateLimit();
            b.rateLimiter(new RateLimiter(rl.getRequestsPerMinute(), Duration.ofMinutes(1), rl.getMaxKeys(), Clock.systemUTC()));
        }
        SecureProperties.Cors c = props.getCors();
        if (c.getAllowedOrigins() != null && !c.getAllowedOrigins().isEmpty()) {
            b.cors(CorsPolicy.builder()
                    .allowOrigins(c.getAllowedOrigins().toArray(new String[0]))
                    .allowMethods(c.getAllowedMethods().toArray(new String[0]))
                    .allowHeaders(c.getAllowedHeaders().toArray(new String[0]))
                    .exposeHeaders(c.getExposedHeaders().toArray(new String[0]))
                    .allowCredentials(c.isAllowCredentials())
                    .maxAgeSeconds(c.getMaxAgeSeconds())
                    .build());
        }
        listeners.orderedStream().forEach(b::listener);
        return b.build();
    }

    @Bean
    public FilterRegistrationBean<SecurityFilter> secureFilterRegistration(SecurityFilterEngine engine, SecureProperties props) {
        FilterRegistrationBean<SecurityFilter> reg = new FilterRegistrationBean<SecurityFilter>(new SecurityFilter(engine));
        reg.setName("secureFilter");
        reg.setOrder(props.getFilterOrder());
        reg.setUrlPatterns(props.getUrlPatterns());
        return reg;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecureExceptionHandler secureExceptionHandler(SecurityFilterEngine engine, ClaimMapping mapping) {
        return new SecureExceptionHandler(engine, mapping);
    }

    /**
     * The audit log, when {@code secure.audit.file.path} or {@code secure.audit.syslog.host} is set or
     * the application defines an {@link AuditSink} bean. It is a {@link SecurityEventListener}, so the
     * filter's events reach it; {@link Auditor} records the application's own actions.
     */
    @Configuration(proxyBeanMethods = false)
    @Conditional(AuditConfigured.class)
    static class AuditConfiguration {

        @Bean
        @ConditionalOnMissingBean
        AuditLog secureAuditLog(SecureProperties props, ObjectProvider<AuditSink> sinks, Environment env) throws IOException {
            SecureProperties.Audit a = props.getAudit();
            AuditLog.Builder b = AuditLog.builder().queueCapacity(a.getQueueCapacity()).closeOnShutdown(false);
            SecureProperties.Audit.File f = a.getFile();
            if (StringUtils.hasText(f.getPath())) {
                FileAuditSink.Builder fb = FileAuditSink.builder(Paths.get(f.getPath())).format(f.getFormat())
                        .maxBytes(f.getMaxBytes()).maxFiles(f.getMaxFiles()).hashChain(f.isHashChain());
                if (StringUtils.hasText(f.getHmacKey())) {
                    fb.hmacKey(f.getHmacKey().getBytes(StandardCharsets.UTF_8));
                }
                b.sink(fb.build());
            }
            SecureProperties.Audit.Syslog s = a.getSyslog();
            if (StringUtils.hasText(s.getHost())) {
                int port = s.getPort() != null ? s.getPort() : s.getProtocol() == SyslogAuditSink.Protocol.TLS ? 6514 : 514;
                String app = s.getAppName() != null ? s.getAppName() : env.getProperty("spring.application.name", "secure");
                b.sink(SyslogAuditSink.builder(s.getHost(), port).protocol(s.getProtocol()).format(s.getFormat())
                        .appName(app).facility(s.getFacility()).build());
            }
            sinks.orderedStream().forEach(b::sink);
            return b.build();
        }

        @Bean
        @ConditionalOnMissingBean
        Auditor secureAuditor(AuditLog log, ClaimMapping mapping) {
            return new Auditor(log, mapping);
        }

        /** Separate, so the Spring Security types are only loaded when Spring Security is present. */
        @Configuration(proxyBeanMethods = false)
        @ConditionalOnClass(name = "org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent")
        @ConditionalOnProperty(prefix = "secure.audit", name = "authentication-failures", havingValue = "true", matchIfMissing = true)
        static class AuthenticationAudit {

            @Bean
            AuthenticationFailureAudit secureAuthenticationFailureAudit(AuditLog log) {
                return new AuthenticationFailureAudit(log);
            }
        }
    }

    /** Any one of: a file path, a syslog host, or an {@link AuditSink} bean. */
    static class AuditConfigured extends AnyNestedCondition {

        AuditConfigured() {
            super(ConfigurationPhase.REGISTER_BEAN);
        }

        @ConditionalOnProperty(prefix = "secure.audit.file", name = "path")
        static class FilePath {
        }

        @ConditionalOnProperty(prefix = "secure.audit.syslog", name = "host")
        static class SyslogHost {
        }

        @ConditionalOnBean(AuditSink.class)
        static class CustomSink {
        }
    }

    /** {@link CurrentUser} needs Spring Security to know who is logged in. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.security.core.context.SecurityContextHolder")
    static class CurrentUserConfiguration implements WebMvcConfigurer {

        private final ClaimMapping mapping;

        CurrentUserConfiguration(ClaimMapping mapping) {
            this.mapping = mapping;
        }

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
            resolvers.add(new CurrentUserArgumentResolver(mapping));
        }
    }
}
