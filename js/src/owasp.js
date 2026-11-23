/**
 * OWASP Top 10 categories, ordered as in the current edition. OWASP publishes it as
 * "Top 10:2025" (owasp.org/Top10/2025) and it is the list in force during 2026; there is
 * no separate 2026 web edition. The 2021 ids are kept for teams still mapping old reports.
 */
export const OwaspCategory = Object.freeze({
  BROKEN_ACCESS_CONTROL: { id2025: 'A01:2025', id2021: 'A01:2021', title: 'Broken Access Control' },
  SECURITY_MISCONFIGURATION: { id2025: 'A02:2025', id2021: 'A05:2021', title: 'Security Misconfiguration' },
  SUPPLY_CHAIN_FAILURES: { id2025: 'A03:2025', id2021: 'A06:2021', title: 'Software Supply Chain Failures' },
  CRYPTOGRAPHIC_FAILURES: { id2025: 'A04:2025', id2021: 'A02:2021', title: 'Cryptographic Failures' },
  INJECTION: { id2025: 'A05:2025', id2021: 'A03:2021', title: 'Injection' },
  INSECURE_DESIGN: { id2025: 'A06:2025', id2021: 'A04:2021', title: 'Insecure Design' },
  AUTHENTICATION_FAILURES: { id2025: 'A07:2025', id2021: 'A07:2021', title: 'Authentication Failures' },
  INTEGRITY_FAILURES: { id2025: 'A08:2025', id2021: 'A08:2021', title: 'Software or Data Integrity Failures' },
  LOGGING_ALERTING_FAILURES: { id2025: 'A09:2025', id2021: 'A09:2021', title: 'Security Logging and Alerting Failures' },
  EXCEPTIONAL_CONDITIONS: { id2025: 'A10:2025', id2021: null, title: 'Mishandling of Exceptional Conditions' },
  /** Folded into A01 in 2025; kept separate so SSRF findings stay identifiable. */
  SSRF: { id2025: 'A01:2025', id2021: 'A10:2021', title: 'Server-Side Request Forgery' },
});

/** Base type for every rejection raised by this library. Messages are safe to log, not to show users. */
export class SecurityViolationError extends Error {
  constructor(category, message) {
    super(message);
    this.name = 'SecurityViolationError';
    this.category = category;
  }
}
