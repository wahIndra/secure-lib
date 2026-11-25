# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org); the same version
is published to Maven Central (`io.github.wahindra:*`) and npm (`@wahindra/secure`).

## [0.2.0] - 2026-11-25

### Added
- **Spring Boot starter** `secure-spring-boot-starter` for Spring Boot 3 and 4 (Java 17+). It
  auto-registers the request filter before Spring Security, injects `@CurrentUser
  SecurityPrincipal` from the verified token, returns safe 401/403/400 responses, wires
  `SecurityEventListener` beans, and is configured through `secure.*` properties. End-to-end
  tests start a real app and attack it with `secure probe` and `secure idor`, on Spring Boot 3.5
  and 4.2.
- **Identity from verified tokens, for any OIDC provider**: `ClaimsPrincipal` / `ClaimMapping`
  (Java) and `principalFromVerifiedClaims` / `ClaimMappings` (JS), with presets for Keycloak,
  Auth0, Microsoft Entra ID, Okta and AWS Cognito. Express `currentUser()` middleware.
- **IDOR / BOLA checks**: scan rule `IDOR_IDENTITY_FROM_REQUEST` (user id taken from the
  request instead of the token), and `secure idor`, which fetches an object as its owner, as
  another user and logged out.
- **JSON body inspection** in the servlet filters, for any HTTP method and also when the length
  is unknown (HTTP/2 needs no `Content-Length`). The body is read once, decoded the way Jackson
  does (UTF-8/16/32 detected from the bytes, plus the declared charset, strictly), inspected, and
  replayed unchanged to the application. A body that fails any of these decodings is rejected.
- **Per-request inspection budget** (values, characters, nesting depth). A request over the
  budget counts as malicious instead of being partly skipped.
- **Rate limiting** for any endpoint: `RateLimiter` (token bucket per key, bounded memory, 429
  with `Retry-After` and `RateLimit-*` headers), Express `rateLimit()`.
- **Strict CORS**: `CorsPolicy`, Express `cors()`, `secure.cors.*`.
- **Safe redirects**: `SafeRedirect.target(...)` / `safeRedirect(...)`.
- **Security events** for alerting (A09): `SecurityEvent` / `SecurityEventListener` (Java),
  `onEvent` (JS); `LoginAttemptLimiter.onLockout(...)`; `ACCESS_DENIED` events from the
  starter's and Express's error handlers.
- `SecurityFilterEngine`: the filter logic shared by every adapter, usable from any framework.
- Servlet filter tests for both javax and jakarta; TypeScript definitions type-checked in CI.

### Changed
- The javax and jakarta `SecurityFilter`s are now thin adapters over `SecurityFilterEngine`.
  Existing constructors and `web.xml` init-params keep working; new init-params:
  `inspectJsonBody`, `maxBodyBytes`, `rateLimitPerMinute`, `corsAllowedOrigins`,
  `corsAllowCredentials`.
- Request inspection limits are now `maxValues` 2,000 (was 500 parameters), `maxInspectedChars`
  256 K, and nesting depth 20 (JS was 10), the same in Java and JavaScript.

### Fixed
- `LoginAttemptLimiter` memory cap: evicts the weakest entry instead of letting the map grow or
  blocking new accounts; expired entries go before live ones.
- `ClaimsPrincipal` never splits role names ("Team admin" no longer grants "admin").
- Release workflow: npm publishing through trusted publishing, and building exactly the commit
  that was checked.

## [0.1.0] - 2026-11-24

First release: detectors (SQL injection with PostgreSQL-specific rules, XSS, command / JNDI
injection, path traversal), guards (access control, path traversal, SSRF, safe SQL, safe
commands, output encoding, password hashing, CSRF, HMAC, safe deserialization, log sanitizing,
safe errors), javax and jakarta servlet filters, Express middleware, and the developer tools
`secure scan`, `secure check` and `secure probe`.

[0.2.0]: https://github.com/wahIndra/secure-lib/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/wahIndra/secure-lib/releases/tag/v0.1.0
