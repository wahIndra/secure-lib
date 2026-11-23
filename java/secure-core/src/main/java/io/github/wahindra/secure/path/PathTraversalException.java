package io.github.wahindra.secure.path;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;

public class PathTraversalException extends SecurityViolationException {
    private static final long serialVersionUID = 1L;

    public PathTraversalException(String message) {
        super(OwaspCategory.BROKEN_ACCESS_CONTROL, message);
    }
}
