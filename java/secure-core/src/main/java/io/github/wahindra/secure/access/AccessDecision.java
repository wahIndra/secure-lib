package io.github.wahindra.secure.access;

public final class AccessDecision {

    private final boolean allowed;
    private final String reason;
    private final String matchedRule;
    private final boolean unauthenticated;

    private AccessDecision(boolean allowed, String reason, String matchedRule, boolean unauthenticated) {
        this.allowed = allowed;
        this.reason = reason;
        this.matchedRule = matchedRule;
        this.unauthenticated = unauthenticated;
    }

    static AccessDecision allow(String matchedRule) {
        return new AccessDecision(true, "allowed", matchedRule, false);
    }

    static AccessDecision deny(String reason, String matchedRule, boolean unauthenticated) {
        return new AccessDecision(false, reason, matchedRule, unauthenticated);
    }

    public boolean isAllowed() { return allowed; }
    public String getReason() { return reason; }
    /** The rule that decided, or {@code null} when the default deny applied. */
    public String getMatchedRule() { return matchedRule; }
    public boolean isUnauthenticated() { return unauthenticated; }

    @Override
    public String toString() {
        return (allowed ? "ALLOW" : "DENY") + " (" + reason + (matchedRule != null ? ", rule=" + matchedRule : "") + ")";
    }
}
