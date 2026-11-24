# OWASP Top 10 coverage

The reference is the current **OWASP Top 10:2025** (owasp.org/Top10/2025). It is the edition in
force in 2026; OWASP has not published a separate 2026 web-application list. (The OWASP Top 10
for **LLM Applications** does have a 2026 edition, which is a different list.) The 2021 ids are
shown for teams with older reports.

| 2025 | 2021 | Category | Java (`io.github.wahindra.secure.*`) | JavaScript (`@wahindra/secure`) |
|---|---|---|---|---|
| A01 | A01 | Broken Access Control | `access.RouteAccessPolicy` (deny-by-default, path canonicalization), `access.AccessGuard` (owner/IDOR, tenant, roles, mass assignment), `access.ClaimsPrincipal` + `access.ClaimMapping` (identity from verified tokens: Keycloak, Auth0, Entra ID, Okta, Cognito, any OIDC), `secure idor`, `path.PathTraversalGuard`, `path.SafeFileName`, `path.PathTraversalDetector`, `web.CsrfTokenService`, `web.CorsPolicy`, `web.SafeRedirect`, starter `@CurrentUser` | `RouteAccessPolicy`, `AccessGuard` (also blocks `__proto__` pollution), `principalFromVerifiedClaims` + `ClaimMappings`, `secure idor`, `PathTraversalGuard`, `SafeFileName`, `pathTraversalDetector`, `CsrfTokenService`, `routePolicy()`, `csrfProtection()`, `CorsPolicy` / `cors()`, `safeRedirect`, `currentUser()` |
| A01 | A10 | SSRF (merged into A01 in 2025) | `ssrf.UrlGuard` | `UrlGuard`, `isBlockedAddress` |
| A02 | A05 | Security Misconfiguration | `web.SecurityHeaders`, servlet `SecurityFilter`, `web.SecurityFilterEngine`, `secure-spring-boot-starter` | `securityHeaders()`, `LEAKY_HEADERS`, `securityMiddleware()` |
| A03 | A06 | Software Supply Chain Failures | not a runtime concern; zero dependencies; run Dependency-Check / `npm audit` in CI | same |
| A04 | A02 | Cryptographic Failures | `crypto.PasswordHasher` (PBKDF2-SHA256, 600k), `crypto.SecureTokens`, `integrity.HmacSigner` | `PasswordHasher`, `randomToken`, `constantTimeEquals`, `HmacSigner` |
| A05 | A03 | Injection (SQL, XSS, OS command, JNDI, EL, SSTI) | `injection.SqlInjectionDetector`, `injection.SafeSql`, `injection.XssDetector`, `injection.Encode`, `injection.CommandInjectionDetector`, `injection.SafeCommand`, `InputInspector` | `sqlInjectionDetector`, `SafeSql`, `xssDetector`, `forHtml`/`forJavaScript`/..., `commandInjectionDetector`, `safeCommand`, `inputInspector` |
| A06 | A04 | Insecure Design | `web.RateLimiter`, `crypto.LoginAttemptLimiter`, deny-by-default policy, `HttpRequestInspector` inspection budget | `RateLimiter` / `rateLimit()`, `LoginAttemptLimiter`, inspection budget |
| A07 | A07 | Authentication Failures | `crypto.PasswordPolicy`, `crypto.LoginAttemptLimiter`, `crypto.PasswordHasher` | `validatePassword`, `LoginAttemptLimiter`, `PasswordHasher` |
| A08 | A08 | Software or Data Integrity Failures | `integrity.SafeObjectInputStream` (deserialization allowlist), `integrity.HmacSigner` (webhooks, signed data) | `HmacSigner.verifyHex` (webhooks) |
| A09 | A09 | Security Logging and Alerting Failures | `web.SecurityEvent` + `SecurityEventListener`, `LoginAttemptLimiter.onLockout`, `logging.LogSanitizer` (CRLF, secrets), filter incident logging | `onEvent` / `securityEvent`, `onLockout`, `sanitizeForLog`, `maskSecrets`, middleware incident logging |
| A10 | new | Mishandling of Exceptional Conditions | `errors.SafeErrors`, filter fail-closed by default | `logError`, `publicErrorBody`, `errorHandler()`, middleware fail-closed by default |
