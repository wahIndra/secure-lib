# @wahindra/secure

[![CI](https://github.com/wahIndra/secure-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/wahIndra/secure-lib/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@wahindra/secure)](https://www.npmjs.com/package/@wahindra/secure)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/wahIndra/secure-lib/blob/main/LICENSE)

OWASP Top 10 protection for Node.js 18+: request inspection middleware for Express (or any
`(req, res, next)` stack), access-control guards, identity from any OIDC provider, rate
limiting, strict CORS, SSRF and path-traversal guards, password hashing, and a CLI that finds
vulnerable code and attacks your local app before you deploy. Zero dependencies, ESM, with
TypeScript types.

The same library exists for Java 8+ (Maven Central `io.github.wahindra`), with the same rules
and test vectors: <https://github.com/wahIndra/secure-lib>.

```bash
npm install @wahindra/secure
```

## Protect an Express app

```js
import express from 'express';
import { CorsPolicy, RateLimiter } from '@wahindra/secure';
import { securityMiddleware, errorHandler } from '@wahindra/secure/express';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));          // parse first, so JSON bodies are inspected
app.use(securityMiddleware({
  mode: 'monitor',                                 // start here, then switch to 'block' (the default)
  cors: new CorsPolicy({ allowOrigins: ['https://app.example.com'], allowCredentials: true }),
  rateLimiter: RateLimiter.perMinute(300),         // per client address
  onEvent: (event) => siem.send(event),            // blocked requests, 429s, access denials...
}));

// ... routes ...

app.use(errorHandler());                           // 401/403/400/500 with an incident id, no stack traces
```

Per request, in this order: security headers (CSP, HSTS, nosniff, frame-ancestors...); CORS,
with preflights answered 204 or 403; the rate limit (429 with `Retry-After`); then inspection of
the path, query, parsed body and selected headers for SQL injection (including PostgreSQL
`pg_sleep`, `RAISE EXCEPTION`, `version()` CAST and `EXECUTE` probes), XSS, command / JNDI
injection and path traversal. The input is fully decoded first: URL, HTML-entity, Unicode and
comment-splitting tricks. In `block` mode a malicious request gets a generic 400; in `monitor`
mode it is only reported. Inspection has a budget (2,000 values, 256 K characters, depth 20),
and a request over it counts as malicious.

## Users may only see their own data (IDOR)

Logging in proves who someone is, not what they may read. Take the user from the **verified**
token, never from the request, and check ownership:

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { principalFromVerifiedClaims, ClaimMappings, AccessGuard } from '@wahindra/secure';

const issuer = 'https://idp.example.com/realms/shop';
const jwks = createRemoteJWKSet(new URL(`${issuer}/protocol/openid-connect/certs`));
const IDP = ClaimMappings.keycloak({ clientId: 'orders-api' }); // or auth0(), entraId(), okta(), cognito(), custom()

app.use('/api', async (req, res, next) => {
  try {
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    const { payload } = await jwtVerify(token, jwks, { issuer, audience: 'orders-api' });
    req.user = principalFromVerifiedClaims(payload, IDP);
    next();
  } catch {
    res.status(401).end();
  }
});

app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  AccessGuard.requireOwnerOrRole(req.user, order.ownerId, 'admin');   // AccessDeniedError -> 403
  res.json(order);
});
```

With `express-oauth2-jwt-bearer`, `currentUser(IDP)` from `@wahindra/secure/express` sets
`req.user` from `req.auth.payload` for you.

## Guards

| Need | Use |
|---|---|
| Deny-by-default routes | `new RouteAccessPolicy().permitAll('GET', '/public/**').hasAnyRole('*', '/admin/**', 'ADMIN').authenticated('*', '/api/**')`, `routePolicy(policy)` |
| Ownership, tenant, mass assignment, prototype pollution | `AccessGuard.requireOwner / requireOwnerOrRole / requireSameTenant / requireNoProtectedFields(req.body, 'role')` |
| Files from user input | `PathTraversalGuard.forBaseDirectory('/srv/uploads').resolve(req.params.name)`, `SafeFileName.sanitize(name)` |
| Outbound URLs (webhooks, previews) | `await new UrlGuard({ allowHosts: ['*.partner.com'] }).validate(url)` blocks internal, loopback and metadata addresses |
| Redirects | `res.redirect(safeRedirect(req.query.next, '/', ['accounts.example.com']))` |
| SQL that can't use placeholders | `SafeSql.allowlisted(sort, ['created_at', 'total'])`, `SafeSql.direction(dir)`, `SafeSql.escapeLike(q)` |
| Running programs | `const [cmd, args] = safeCommand('/usr/bin/convert', [input, output]); execFile(cmd, args)` |
| HTML you build by hand | `forHtml`, `forHtmlAttribute`, `forJavaScript`, `forUrlComponent`, `safeUrl` |
| Passwords and logins | `await new PasswordHasher().hash(pw)` (PBKDF2-SHA256, 600k iterations; same format as the Java library), `validatePassword(pw, { username })`, `new LoginAttemptLimiter().onLockout(alert)` |
| Tokens, CSRF, webhooks | `randomToken()`, `constantTimeEquals`, `new CsrfTokenService(key)`, `csrfProtection(service)`, `new HmacSigner(secret).verifyHex(rawBody, signature)` |
| Rate limits per route | `app.post('/login', rateLimit(RateLimiter.perMinute(10)), login)` |
| Logs and errors | `sanitizeForLog(value)` (CRLF, secrets masked), `logError(logger, err)` + `publicErrorBody(id)` |

## Developer tools: `npx secure`

```bash
npx secure scan src/                       # vulnerable code, with the fix, as clickable file:line:col
npx secure check "1;SELECT pg_sleep(5)--"  # how the middleware sees a value and which rules match
npx secure probe "http://localhost:3000/search?q=FUZZ"   # attack YOUR local app with 44 payloads
npx secure idor http://localhost:3000/api/orders/42 \
  --as-owner "Authorization: Bearer $TOKEN_A" --as-other "Authorization: Bearer $TOKEN_B"
```

- **`scan`** has 55 rules: SQL / NoSQL / command injection, XSS sinks, path traversal, SSRF,
  open redirects, IDOR, weak crypto, hard-coded secrets, unverified JWTs, unsafe
  deserialization, CORS `*`, and more. It covers JS/TS, Java, templates and config files.
  Formats: text, JSON, SARIF. It exits 1 on HIGH findings, so it can gate CI or a pre-commit
  hook. Silence a reviewed finding with `// secure-scan:ignore RULE_ID -- reason`.
- **`probe`** reports SQL errors, time delays, reflected XSS, file contents, command output and
  template evaluation in responses.
- **`idor`** checks that only the owner can fetch an object. It works with any login (bearer
  token, cookie, API key).
- `probe` and `idor` only target local and private addresses, unless you pass
  `--allow-remote` for systems you are authorized to test.

As a test, so `npm test` fails before deploy:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SourceScanner, atLeast, toText } from '@wahindra/secure/devtools';

test('no HIGH security findings', () => {
  const report = new SourceScanner().scan('src');
  assert.deepEqual(atLeast(report.findings, 'HIGH'), [], toText(report));
});
```

## More

- Full documentation, the Java and Spring Boot versions, benchmarks and the OWASP Top 10 mapping:
  <https://github.com/wahIndra/secure-lib>
- Changes per version: [CHANGELOG](https://github.com/wahIndra/secure-lib/blob/main/CHANGELOG.md)
- The detectors are a safety net, not a replacement for parameterized queries, output encoding
  and access checks in your code.

MIT License.
