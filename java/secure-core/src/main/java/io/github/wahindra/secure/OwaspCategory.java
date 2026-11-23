package io.github.wahindra.secure;

/**
 * OWASP Top 10 categories, ordered as in the current edition. OWASP publishes it as
 * "Top 10:2025" (owasp.org/Top10/2025) and it is the list in force during 2026; there is
 * no separate 2026 web edition. The 2021 ids are kept for teams still mapping old reports.
 */
public enum OwaspCategory {
    BROKEN_ACCESS_CONTROL("A01:2025", "A01:2021", "Broken Access Control"),
    SECURITY_MISCONFIGURATION("A02:2025", "A05:2021", "Security Misconfiguration"),
    SUPPLY_CHAIN_FAILURES("A03:2025", "A06:2021", "Software Supply Chain Failures"),
    CRYPTOGRAPHIC_FAILURES("A04:2025", "A02:2021", "Cryptographic Failures"),
    INJECTION("A05:2025", "A03:2021", "Injection"),
    INSECURE_DESIGN("A06:2025", "A04:2021", "Insecure Design"),
    AUTHENTICATION_FAILURES("A07:2025", "A07:2021", "Authentication Failures"),
    INTEGRITY_FAILURES("A08:2025", "A08:2021", "Software or Data Integrity Failures"),
    LOGGING_ALERTING_FAILURES("A09:2025", "A09:2021", "Security Logging and Alerting Failures"),
    EXCEPTIONAL_CONDITIONS("A10:2025", null, "Mishandling of Exceptional Conditions"),
    /** Folded into A01 in 2025; kept separate so SSRF findings stay identifiable. */
    SSRF("A01:2025", "A10:2021", "Server-Side Request Forgery");

    private final String id2025;
    private final String id2021;
    private final String title;

    OwaspCategory(String id2025, String id2021, String title) {
        this.id2025 = id2025;
        this.id2021 = id2021;
        this.title = title;
    }

    public String id2025() { return id2025; }

    /** May be {@code null} when the category did not exist in 2021. */
    public String id2021() { return id2021; }

    public String title() { return title; }
}
