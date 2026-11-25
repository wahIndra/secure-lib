package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.audit.AuditLog;
import io.github.wahindra.secure.errors.SafeErrors;
import io.github.wahindra.secure.web.SecurityEvent;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Records Spring Security's failed authentications (wrong password, invalid or expired bearer
 * token) as {@code LOGIN_FAILED}. The user name is recorded only for username/password logins:
 * for a bearer token, Spring's "name" is the token itself, which must never be logged.
 */
public final class AuthenticationFailureAudit implements ApplicationListener<AbstractAuthenticationFailureEvent> {

    private final AuditLog log;

    public AuthenticationFailureAudit(AuditLog log) {
        this.log = log;
    }

    @Override
    public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
        Authentication auth = event.getAuthentication();
        SecurityEvent.Builder b = SecurityEvent.builder(SecurityEvent.Type.LOGIN_FAILED, SafeErrors.newIncidentId())
                .category(OwaspCategory.AUTHENTICATION_FAILURES)
                .detail(event.getException().getClass().getSimpleName());
        if (auth instanceof UsernamePasswordAuthenticationToken && auth.getPrincipal() instanceof String) {
            b.principalId((String) auth.getPrincipal());
        }
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes) {
            HttpServletRequest req = ((ServletRequestAttributes) attrs).getRequest();
            b.method(req.getMethod()).path(req.getRequestURI()).remoteAddress(req.getRemoteAddr());
        }
        log.onEvent(b.build());
    }
}
