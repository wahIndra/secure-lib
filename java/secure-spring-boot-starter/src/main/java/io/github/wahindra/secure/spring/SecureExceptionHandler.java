package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;
import io.github.wahindra.secure.access.AccessDeniedException;
import io.github.wahindra.secure.access.ClaimMapping;
import io.github.wahindra.secure.access.SecurityPrincipal;
import io.github.wahindra.secure.errors.SafeErrors;
import io.github.wahindra.secure.web.SecurityEvent;
import io.github.wahindra.secure.web.SecurityFilterEngine;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns the library's exceptions into safe responses: {@link AccessDeniedException} becomes 401
 * or 403, any other {@link SecurityViolationException} 400. Bodies carry only a code and an
 * incident id, never the reason, and access denials are reported as {@code ACCESS_DENIED} events.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecureExceptionHandler {

    private static final boolean SECURITY_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.core.context.SecurityContextHolder", SecureExceptionHandler.class.getClassLoader());

    private final SecurityFilterEngine engine;
    private final ClaimMapping mapping;

    public SecureExceptionHandler(SecurityFilterEngine engine, ClaimMapping mapping) {
        this.engine = engine;
        this.mapping = mapping;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> accessDenied(AccessDeniedException e, HttpServletRequest request) {
        String id = SafeErrors.newIncidentId();
        String principal = null;
        if (SECURITY_PRESENT && !e.isUnauthenticated()) {
            try {
                SecurityPrincipal p = CurrentUserArgumentResolver.current(mapping);
                principal = p == null ? null : p.getId();
            } catch (RuntimeException ignored) {
                // The event is still useful without the user id.
            }
        }
        engine.emit(SecurityEvent.builder(SecurityEvent.Type.ACCESS_DENIED, id).method(request.getMethod())
                .path(request.getRequestURI()).remoteAddress(request.getRemoteAddr()).principalId(principal)
                .category(OwaspCategory.BROKEN_ACCESS_CONTROL).detail(e.getMessage()).build());
        HttpStatus status = e.isUnauthenticated() ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN;
        return body(status, e.isUnauthenticated() ? "unauthenticated" : "forbidden", id);
    }

    @ExceptionHandler(SecurityViolationException.class)
    public ResponseEntity<String> violation(SecurityViolationException e) {
        String id = SafeErrors.newIncidentId();
        return body(HttpStatus.BAD_REQUEST, "request_rejected", id);
    }

    private static ResponseEntity<String> body(HttpStatus status, String code, String id) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"" + code + "\",\"incidentId\":\"" + id + "\"}");
    }
}
