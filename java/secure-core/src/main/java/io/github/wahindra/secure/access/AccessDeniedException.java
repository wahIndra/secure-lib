package io.github.wahindra.secure.access;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;

/** Map to HTTP 403 (or 404 when revealing that the resource exists is itself a leak). */
public class AccessDeniedException extends SecurityViolationException {
    private static final long serialVersionUID = 1L;

    private final boolean unauthenticated;

    public AccessDeniedException(String message) {
        this(message, false);
    }

    public AccessDeniedException(String message, boolean unauthenticated) {
        super(OwaspCategory.BROKEN_ACCESS_CONTROL, message);
        this.unauthenticated = unauthenticated;
    }

    /** {@code true} when there was no principal at all; map to HTTP 401. */
    public boolean isUnauthenticated() {
        return unauthenticated;
    }
}
