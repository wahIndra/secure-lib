package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.access.ClaimMapping;
import io.github.wahindra.secure.access.SecurityPrincipal;
import io.github.wahindra.secure.audit.AuditLog;
import io.github.wahindra.secure.audit.AuditRecord;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.ClassUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Records application actions in the audit log, with the user (from the verified token), client
 * address, method and path of the current request filled in:
 *
 * <pre>
 * &#64;PostMapping("/api/orders/{id}/refund")
 * void refund(&#64;PathVariable long id) {
 *     ...
 *     auditor.record("order.refund", "order/" + id, AuditRecord.Outcome.SUCCESS);
 * }
 * </pre>
 *
 * <p>Outside a request (a scheduled job), only what you pass is recorded.
 */
public final class Auditor {

    private static final boolean SECURITY_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.core.context.SecurityContextHolder", Auditor.class.getClassLoader());

    private final AuditLog log;
    private final ClaimMapping mapping;

    public Auditor(AuditLog log, ClaimMapping mapping) {
        this.log = log;
        this.mapping = mapping;
    }

    /** @return {@code false} if the record was dropped (queue full) */
    public boolean record(String event, String resource, AuditRecord.Outcome outcome) {
        return record(AuditRecord.builder(event).resource(resource).outcome(outcome));
    }

    public boolean record(String event, String resource, AuditRecord.Outcome outcome, String detail) {
        return record(AuditRecord.builder(event).resource(resource).outcome(outcome).detail(detail));
    }

    /** Fills in user and request details the builder does not already have, then records. */
    public boolean record(AuditRecord.Builder builder) {
        AuditRecord draft = builder.build();
        if (draft.getPrincipalId() == null) {
            builder.principalId(currentUser());
        }
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes) {
            HttpServletRequest req = ((ServletRequestAttributes) attrs).getRequest();
            if (draft.getRemoteAddress() == null) {
                builder.remoteAddress(req.getRemoteAddr());
            }
            if (draft.getMethod() == null) {
                builder.method(req.getMethod());
            }
            if (draft.getPath() == null) {
                builder.path(req.getRequestURI());
            }
        }
        return log.record(builder.build());
    }

    /** The underlying log, e.g. for {@code droppedCount()} in a health check. */
    public AuditLog getLog() {
        return log;
    }

    private String currentUser() {
        if (!SECURITY_PRESENT) {
            return null;
        }
        try {
            SecurityPrincipal p = CurrentUserArgumentResolver.current(mapping);
            return p == null ? null : p.getId();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
