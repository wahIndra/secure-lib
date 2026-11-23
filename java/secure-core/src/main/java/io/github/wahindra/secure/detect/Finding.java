package io.github.wahindra.secure.detect;

import io.github.wahindra.secure.OwaspCategory;

/** A single rule match. Contains no part of the input, so it is always safe to log. */
public final class Finding {
    private final String ruleId;
    private final OwaspCategory category;
    private final Severity severity;
    private final String description;

    public Finding(String ruleId, OwaspCategory category, Severity severity, String description) {
        this.ruleId = ruleId;
        this.category = category;
        this.severity = severity;
        this.description = description;
    }

    public String getRuleId() { return ruleId; }
    public OwaspCategory getCategory() { return category; }
    public Severity getSeverity() { return severity; }
    public String getDescription() { return description; }

    @Override
    public String toString() {
        return ruleId + "[" + severity + "]";
    }
}
