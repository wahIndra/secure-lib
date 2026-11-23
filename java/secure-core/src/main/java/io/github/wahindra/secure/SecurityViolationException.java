package io.github.wahindra.secure;

/** Base type for every rejection raised by this library. Messages are safe to log, not to show users. */
public class SecurityViolationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final OwaspCategory category;

    public SecurityViolationException(OwaspCategory category, String message) {
        super(message);
        this.category = category;
    }

    public OwaspCategory getCategory() { return category; }
}
