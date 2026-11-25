# secure-lib

[![CI](https://github.com/wahIndra/secure-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/wahIndra/secure-lib/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.wahindra/secure-core?label=maven%20central)](https://central.sonatype.com/namespace/io.github.wahindra)
[![npm](https://img.shields.io/npm/v/@wahindra/secure)](https://www.npmjs.com/package/@wahindra/secure)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Java 8+](https://img.shields.io/badge/java-8%2B-orange)
![Node 20+](https://img.shields.io/badge/node-20%2B-green)

OWASP Top 10 prevention helpers for **Java 8+** and **Node.js 20+**, with zero runtime dependencies.

```xml
<!-- Maven: Spring Boot 3 / Jakarta EE (see Install below for other stacks) -->
<dependency>
  <groupId>io.github.wahindra</groupId>
  <artifactId>secure-servlet-jakarta</artifactId>
  <version>0.1.0</version>
</dependency>
```

```bash
npm install @wahindra/secure       # Node.js
```

The library has two layers:

1. **Guards** stop the bug itself: path resolution inside a base directory, deny-by-default route
   policy, ownership/tenant checks, SSRF URL validation, safe SQL identifiers, shell-free commands,
   password hashing, CSRF, output encoding and safe deserialization.
2. **Detectors** recognise attack payloads (SQL injection, XSS, command/JNDI injection, path
   traversal) for monitoring and for blocking scanners at the edge. They are a safety net, not a
   replacement for the guards. Parameterized queries are still what stops SQL injection.

Java and JavaScript share the same rule ids, severities and **test vectors** (`test-vectors/`), so a
finding such as `SQLI_PG_SLEEP` means the same thing in both stacks. Password hashes, HMAC
signatures and CSRF tokens use the same format, so either side can verify what the other produced.

- [Compatibility](#compatibility)
- [How to use: Java](#how-to-use-java)
- [How to use: JavaScript](#how-to-use-javascript)
- [API protection: JSON bodies, budgets, rate limits, CORS, redirects, events](#api-protection-json-bodies-budgets-rate-limits-cors-redirects-events)
- [Developer tools: catch it while coding](#developer-tools-catch-it-while-coding)
- [End-to-end check in your own app](#end-to-end-check-in-your-own-app)
- [Coverage](#coverage)
- [Benchmark](#benchmark)
- [Object-level authorization with any identity provider (IDOR / BOLA)](#object-level-authorization-with-any-identity-provider-idor--bola)
- [Continuous integration](#continuous-integration)
- [Rolling it out](#rolling-it-out)
- [Limitations](#limitations)

## Layout

```
java/                     Maven multi-module, compiled with --release 8
  secure-core/            detectors and guards (no dependencies)
  secure-servlet-javax/   Filter for javax.servlet  (Java EE 8, Spring Boot 2, Tomcat 9)
  secure-servlet-jakarta/ Filter for jakarta.servlet (Jakarta EE 9+, Tomcat 10+)
  secure-spring-boot-starter/ Spring Boot 3 / 4 auto-configuration (Java 17+), with end-to-end tests
js/                       ESM package with TypeScript types and Express middleware
  bin/secure.js           developer CLI (npx secure scan | check | probe)
  bench/                  benchmark script
devtools/                 shared by both languages
  scan-rules.txt          55 source-code rules for `secure scan`
  probe-payloads.txt      payloads for `secure probe`
  hooks/pre-commit        git hook that blocks commits with HIGH findings
  ide/vscode-tasks.json   VS Code tasks with a problem matcher (findings in the Problems panel)
test-vectors/             shared payloads, crypto fixtures and scanner fixtures (scan/vulnerable, scan/safe)
docs/OWASP-MAPPING.md     what covers each Top 10 category
.github/
  workflows/ci.yml        build + test matrix, self-scan, Java/JS parity check
  workflows/release.yml   on a vX.Y.Z tag: CI, then Maven Central + npm + GitHub release
  dependabot.yml          weekly Maven, npm and GitHub Actions updates
RELEASING.md              how to cut a release and the one-time account setup
CHANGELOG.md              changes per version
```

## Compatibility

All jars are Java 8 bytecode, so one artifact serves every JVM below. CI runs the full suites on
every push and pull request (see [Continuous integration](#continuous-integration)).

| Runtime | CI (Linux; Windows where noted) | Also verified locally on Windows 11 |
|---|---|---|
| Java 8 | Temurin 8 | Temurin 1.8.0_452 |
| Java 11 | Temurin 11 | |
| Java 17 | Temurin 17 | Temurin and Microsoft 17.0.15 |
| Java 21 | Temurin 21 (Linux + Windows) | Temurin 21.0.7 |
| Java 25 | Temurin 25 | Oracle 25.0.2 |
| Node.js 20 / 22 | 20, 22 | 21.6.2 |
| Node.js 24 / 26 | 24 (Linux + Windows), 26 | 24.22.1, 26.12.1 |
| Spring Boot 3.5 (starter) | end-to-end tests on Java 17, 21, 25 | Temurin 21 |
| Spring Boot 4.2 (starter) | end-to-end tests on Java 21 | Temurin 21 |

The library uses no reflection and no JDK internals, so the Java 17+ module encapsulation does
not affect it.

## How to use: Java

### Install

Published on Maven Central under `io.github.wahindra`, so no extra repository setup is needed.
Every artifact ships with sources and javadoc, and is signed with key
`286896860735D5B2D1A5645E36C71148C2C4FFFE`.

| Your stack | artifactId |
|---|---|
| **Spring Boot 3 or 4** (recommended: everything auto-configured) | `secure-spring-boot-starter` (from 0.2.0) |
| Other Jakarta EE 9+ / Tomcat 10+ apps | `secure-servlet-jakarta` |
| Spring Boot 2, Java EE 8, Tomcat 9 | `secure-servlet-javax` |
| Guards and detectors only (no servlet) | `secure-core` |

```xml
<dependency>
  <groupId>io.github.wahindra</groupId>
  <artifactId>secure-servlet-jakarta</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle: `implementation("io.github.wahindra:secure-servlet-jakarta:0.1.0")`.

Unreleased changes on `main` are available as `0.1.0-SNAPSHOT` after `mvn install` from a
clone (local Maven repository only).

### Build and test

```bash
cd java
mvn verify                  # JDK 8 or newer
mvn -Pcoverage verify       # same, plus a JaCoCo report in secure-core/target/site/jacoco/
mvn -Prelease -Dgpg.skip verify   # also builds the sources and javadoc jars Maven Central requires
```

### Spring Boot starter (Spring Boot 3 and 4)

One dependency registers everything: the request filter (inspection including JSON bodies,
security headers, optional CORS and rate limit), `@CurrentUser` injection from the verified
token, safe 401/403/400 responses for the library's exceptions, and your `SecurityEventListener`
beans. It runs before Spring Security, so attacks are rejected before authentication work.

```xml
<dependency>
  <groupId>io.github.wahindra</groupId>
  <artifactId>secure-spring-boot-starter</artifactId>
  <version>0.2.0</version>
</dependency>
```

```yaml
# application.yml (every value is optional; these are examples, not the defaults)
secure:
  mode: monitor                  # start with monitor in production, then switch to block (the default)
  identity:
    provider: keycloak           # standard | keycloak | auth0 | entra-id | okta | cognito
    client-id: orders-api        # Keycloak client whose roles are granted
  cors:
    allowed-origins: https://app.example.com
    allow-credentials: true
  rate-limit:
    enabled: true
    requests-per-minute: 300     # per client address
  inspection:
    max-body-bytes: 1048576      # larger JSON bodies are rejected in block mode
```

```java
@GetMapping("/api/orders/{id}")
Order order(@PathVariable long id, @CurrentUser SecurityPrincipal user) {   // from the verified token
    Order order = repo.findById(id).orElseThrow(NotFoundException::new);
    AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "admin");      // 403 for anyone else
    return order;
}

@Bean
SecurityEventListener alerts(SlackClient slack) {                          // blocked requests, 429s,
    return event -> slack.post(event.toJson());                            // access denials, lockouts
}
```

All `secure.*` properties are in `SecureProperties`. The starter's tests start a real Spring
Boot app (Spring Security JWT resource server with Keycloak-shaped tokens) on **both Spring Boot
3.5 and 4.2**, and attack it with `secure probe` and `secure idor`. With the starter on, nothing
gets through. With it off, the probe finds the XSS in the same app. See
[the end-to-end check](#end-to-end-check-in-your-own-app).

### 1. Request filter, without Spring Boot (detection + security headers)

Plain servlet containers or Spring Boot 2 (javax). On Spring Boot 3 or 4, prefer the starter above.

```java
import io.github.wahindra.secure.servlet.jakarta.SecurityFilter;
import io.github.wahindra.secure.web.HttpRequestInspector;
import io.github.wahindra.secure.web.SecurityHeaders;

@Bean
FilterRegistrationBean<SecurityFilter> securityFilter() {
    FilterRegistrationBean<SecurityFilter> bean = new FilterRegistrationBean<>(new SecurityFilter(
            SecurityFilter.Mode.MONITOR,                   // start in MONITOR, switch to BLOCK after tuning
            new HttpRequestInspector(),
            SecurityHeaders.builder().noStore().build(),   // or null to leave headers alone
            false));                                       // failOpen: false = reject if inspection itself fails
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return bean;
}
```

Plain `web.xml` (Tomcat 9, WildFly, WebLogic...):

```xml
<filter>
  <filter-name>security</filter-name>
  <filter-class>io.github.wahindra.secure.servlet.javax.SecurityFilter</filter-class>
  <init-param><param-name>mode</param-name><param-value>monitor</param-value></init-param>
  <!-- optional: headers (comma list to inspect), securityHeaders (true|false), failOpen (true|false) -->
</filter>
<filter-mapping><filter-name>security</filter-name><url-pattern>/*</url-pattern></filter-mapping>
```

The filter inspects the path, every parameter name and value, and the `User-Agent`, `Referer`,
`X-Forwarded-*`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL` and `Origin` headers. Blocked
requests get `400 {"error":"request_rejected","incidentId":"..."}`. The log line has the
incident id, the field and the rule ids, but never the payload:

```
security-filter incident=3f2c... action=blocked method=GET uri=/api/orders remote=10.0.0.7 findings=param:id=[SQLI_STACKED_QUERY[HIGH], SQLI_PG_SLEEP[HIGH]]
```

### 2. Guards in application code

```java
// A01 Broken Access Control: deny-by-default routes, then object-level checks
RouteAccessPolicy policy = RouteAccessPolicy.builder()
        .permitAll("GET", "/public/**")
        .permitAll("POST", "/login")
        .hasAnyRole("*", "/admin/**", "ADMIN")
        .authenticated("*", "/api/**")
        .build();                                                   // anything unmatched is denied
policy.check(request.getMethod(), request.getRequestURI(), user);   // throws AccessDeniedException

Order order = repo.findById(id);
AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "ADMIN");  // IDOR
AccessGuard.requireSameTenant(user, order.getTenantId());           // multi-tenant isolation
AccessGuard.requireNoProtectedFields(body.keySet(), "role", "ownerId", "isAdmin");  // mass assignment

// A01 Path traversal
PathTraversalGuard uploads = PathTraversalGuard.forBaseDirectory(Paths.get("/srv/app/uploads"));
Path file = uploads.resolve(request.getParameter("name"));          // throws PathTraversalException
String stored = SafeFileName.sanitize(upload.getOriginalFilename());

// A01 SSRF (folded into A01 in 2025)
UrlGuard guard = UrlGuard.builder().allowHosts("*.partner.com").build();
ValidatedUrl target = guard.validate(webhookUrl);                   // connect to target.getAddresses()

// A05 Injection: parameterize values, allowlist identifiers
String col = SafeSql.allowlisted(sort, Arrays.asList("created_at", "total"));
String sql = "SELECT * FROM orders WHERE owner_id = ? ORDER BY " + col + " " + SafeSql.direction(dir);
Process p = SafeCommand.of("/usr/bin/convert").arg(in).arg(out).build().start();   // no shell
String html = "<p>" + Encode.forHtml(comment) + "</p>";

// A04 / A07 Passwords and login throttling
PasswordHasher hasher = new PasswordHasher();                        // PBKDF2-SHA256, 600k iterations
String hash = hasher.hash(password);
boolean ok = hasher.verify(password, hash);
List<String> problems = new PasswordPolicy().validate(password, username);
LoginAttemptLimiter limiter = new LoginAttemptLimiter();             // 5 failures / 15 min

// A08 Integrity: webhooks and deserialization
boolean genuine = new HmacSigner(secret).verifyHex(rawBody, request.getHeader("X-Hub-Signature-256"));
ObjectInputStream in = new SafeObjectInputStream(stream, "com.acme.dto.");

// A09 / A10 Logging and errors
log.info("user=" + LogSanitizer.sanitize(username));
String incident = SafeErrors.log(LOG, e, "checkout failed");
return ResponseEntity.status(500).body(SafeErrors.publicBody(incident));

// Detection anywhere else (Kafka messages, GraphQL arguments, batch files...)
DetectionResult r = InputInspector.defaults().inspect(value);
if (r.isMalicious()) { /* reject; log r.getFindings() */ }
```

## How to use: JavaScript

```bash
npm install @wahindra/secure
```

ESM only, Node.js 20+, no dependencies, TypeScript types included. To work on the library itself:

```bash
cd js
npm test            # npm run coverage / npm run bench
```

```js
import express from 'express';
import { RouteAccessPolicy, AccessGuard, PathTraversalGuard, UrlGuard, PasswordHasher, SafeSql } from '@wahindra/secure';
import { securityMiddleware, routePolicy, csrfProtection, errorHandler } from '@wahindra/secure/express';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(securityMiddleware({ mode: 'monitor' }));     // path, query, parsed JSON body, headers
app.use(routePolicy(new RouteAccessPolicy()
  .permitAll('GET', '/public/**')
  .hasAnyRole('*', '/admin/**', 'ADMIN')
  .authenticated('*', '/api/**')));

app.get('/api/orders/:id', async (req, res) => {
  const order = await db.orders.find(req.params.id);
  AccessGuard.requireOwnerOrRole(req.user, order.ownerId, 'ADMIN');
  const col = SafeSql.allowlisted(req.query.sort ?? 'created_at', ['created_at', 'total']);
  res.json(order);
});

const uploads = PathTraversalGuard.forBaseDirectory('/srv/app/uploads');
const file = uploads.resolve(req.query.name);                  // throws PathTraversalError

const { addresses } = await new UrlGuard({ allowHosts: ['*.partner.com'] }).validate(webhookUrl);

const hasher = new PasswordHasher();                           // async; same hash format as Java
const hash = await hasher.hash(password);

app.use(errorHandler());   // 401/403/400/500 with an incident id; never a stack trace
```

`AccessGuard.requireNoProtectedFields(req.body, 'role')` also rejects `__proto__`, `constructor`
and `prototype` keys at any depth, which blocks prototype-pollution payloads.

## Object-level authorization with any identity provider (IDOR / BOLA)

**The problem.** With a frontend, an identity provider (Keycloak, Auth0, Entra ID, Okta, Cognito,
any OIDC issuer) and a backend, logging in only proves *who* the user is. If an endpoint then
takes "whose data" from the request, as in `GET /api/orders?userId=alice`, any logged-in user can
change the id and read everyone's data. This is IDOR (Insecure Direct Object Reference), called
BOLA in the OWASP API Security Top 10 (API1:2023), under A01:2025 Broken Access Control here.

**The fix.**
1. Verify the token in the backend: signature, issuer, audience, expiry.
2. Take the user **only from the token** (`sub`, or `oid` for Entra ID), never from the URL, query, body or headers.
3. Check ownership on every object you load.

This library handles steps 2 and 3. Step 1 belongs to your framework or a JOSE library; never decode a token without verifying it.

| Provider | Mapping | User id | Roles from |
|---|---|---|---|
| Keycloak | `ClaimMapping.keycloak("orders-api")` / `ClaimMappings.keycloak({ clientId: 'orders-api' })` | `sub` | `realm_access.roles` + `resource_access.orders-api.roles` |
| Auth0 | `auth0("https://example.com/roles")` / `auth0({ rolesClaim })` | `sub` | your namespaced claim; permissions from `permissions` |
| Microsoft Entra ID | `entraId()` | `oid` (stable across apps) | `roles`; scopes `scp`; tenant `tid` |
| Okta | `okta()` | `sub` | `groups` |
| AWS Cognito | `cognito()` | `sub` | `cognito:groups` |
| Any other OIDC / JWT | `standard()`, or the builder / `custom({...})` | configurable | configurable, dot paths |

**Spring Boot** (resource server, e.g. `spring.security.oauth2.resourceserver.jwt.issuer-uri=https://idp.example.com/realms/shop`):

```java
// Wrong: the caller chooses whose orders to read. secure scan reports IDOR_IDENTITY_FROM_REQUEST.
@GetMapping("/api/orders")
List<Order> orders(@RequestParam String userId) { return repo.findByOwnerId(userId); }

// Right: identity from the verified token, ownership checked on the object.
private static final ClaimMapping IDP = ClaimMapping.keycloak("orders-api");   // or entraId(), okta(), ...

@GetMapping("/api/orders")
List<Order> myOrders(@AuthenticationPrincipal Jwt jwt) {
    return repo.findByOwnerId(ClaimsPrincipal.fromVerifiedClaims(jwt.getClaims(), IDP).getId());
}

@GetMapping("/api/orders/{id}")
Order order(@PathVariable long id, @AuthenticationPrincipal Jwt jwt) {
    SecurityPrincipal user = ClaimsPrincipal.fromVerifiedClaims(jwt.getClaims(), IDP);
    Order order = repo.findById(id).orElseThrow(NotFoundException::new);
    AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "admin");          // 403 for anyone else
    return order;
}
```

**Express** (verify with [`jose`](https://github.com/panva/jose), or `express-oauth2-jwt-bearer`, which puts the claims in `req.auth`):

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { principalFromVerifiedClaims, ClaimMappings, AccessGuard } from '@wahindra/secure';

const issuer = 'https://idp.example.com/realms/shop';
const jwks = createRemoteJWKSet(new URL(`${issuer}/protocol/openid-connect/certs`));
const IDP = ClaimMappings.keycloak({ clientId: 'orders-api' });                 // or entraId(), okta(), ...

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
  AccessGuard.requireOwnerOrRole(req.user, order.ownerId, 'admin');
  res.json(order);
});
```

**Guidelines:**
- Store the token's user id (`sub`, or `oid` for Entra ID) as `ownerId` when records are created.
- Querying by both keys, as in `findByIdAndOwnerId(id, user.getId())`, is better still: other users' records are never loaded, and the response is a 404 that doesn't reveal the record exists.
- Admin endpoints that take a user id on purpose must require a role. The scanner rule skips files with role checks such as `@PreAuthorize` or `requireAnyRole`.
- If one backend accepts tokens from several issuers, ids can collide. Use one mapping per issuer, or store `iss + "|" + sub`.
- Roles are read exactly as named. Each array element is one role, and a group called
  `Team admin` never grants `admin`. Only a permission claim that is a single string (OAuth
  `scope`) is split, on spaces.

**Check it manually** against your local app, with two users' tokens (or session cookies, or API keys):

```bash
secure idor http://localhost:8080/api/orders/42 \
  --as-owner "Authorization: Bearer $TOKEN_ALICE" \
  --as-other "Authorization: Bearer $TOKEN_BOB" \
  --marker "alice@shop.test"
```

```
ok      owner           HTTP 200  allowed, as expected
HIGH    other user      HTTP 200  response contains the owner's marker: broken object level authorization (IDOR). ...
ok      no credentials  HTTP 401  refused (HTTP 401), as expected
```

`--marker` is text that only the owner's data contains. Without it, a 200 response with a
different body is reported as MEDIUM for you to check, because a "my orders" list legitimately
returns each user's own data. Like `probe`, `idor` only targets local and private addresses unless
you pass `--allow-remote`.

## API protection: JSON bodies, budgets, rate limits, CORS, redirects, events

These run inside the filter or middleware (all of them are on in the Spring Boot starter, and
CORS and rate limiting are opt-in), and each one is also available as a standalone class.

| Feature | Java (`io.github.wahindra.secure.web`) | JavaScript | What it stops |
|---|---|---|---|
| **JSON body inspection** | `SecurityFilterEngine`, servlet filters | `securityMiddleware()` (parsed `req.body`) | Injection payloads in API bodies, on any method (Spring binds `@RequestBody` on GET too). The servlet filter reads the body once, decodes it the way Jackson does (UTF-8/16/32 detected from the bytes, plus the declared charset, strictly), and replays it unchanged. A body that won't decode cleanly is rejected. |
| **Inspection budget** | `HttpRequestInspector.builder().maxValues(2000).maxInspectedChars(256 KB).maxJsonDepth(20)` | `new HttpRequestInspector({ maxValues, maxInspectedChars, maxDepth })` | Payloads hidden behind padding, and requests built to burn CPU. Hitting a limit counts as malicious (fail closed). JSON bodies over 1 MB are rejected in block mode. |
| **Rate limiting** | `RateLimiter.perMinute(300)`; `secure.rate-limit.*` | `RateLimiter.perMinute(300)`, `rateLimit()` middleware | Scraping, enumeration, brute force on any endpoint. Token bucket per key, 429 with `Retry-After` and `RateLimit-*` headers, bounded memory. |
| **Strict CORS** | `CorsPolicy.builder().allowOrigins(...)`; `secure.cors.*` | `new CorsPolicy({ allowOrigins })`, `cors()` middleware | Any origin reading your API with the user's cookies. Never reflects `Origin`, never allows `null`, refuses `*` with credentials, answers preflights directly. |
| **Safe redirects** | `SafeRedirect.target(next, "/", "accounts.example.com")` | `safeRedirect(next, '/', ['accounts.example.com'])` | Open redirects: `//evil`, `/\evil`, `/%2F%2Fevil`, `javascript:`, `https://good@evil`, header injection. |
| **Security events** | `SecurityEventListener`; `LoginAttemptLimiter.onLockout(...)` | `onEvent` option; `limiter.onLockout(...)` | Attacks nobody notices (A09). `REQUEST_BLOCKED`, `REQUEST_FLAGGED`, `RATE_LIMITED`, `CORS_REJECTED`, `ACCESS_DENIED`, `LOGIN_LOCKED`, `INSPECTION_ERROR` as sanitized events (`toJson()` gives one line for a SIEM). |

```java
// Without Spring Boot: the same engine powers the javax and jakarta filters.
SecurityFilterEngine engine = SecurityFilterEngine.builder()
        .mode(SecurityFilterEngine.Mode.BLOCK)
        .cors(CorsPolicy.builder().allowOrigins("https://app.example.com").allowCredentials(true).build())
        .rateLimiter(RateLimiter.perMinute(300))
        .listener(event -> siemQueue.offer(event.toJson()))
        .build();
servletContext.addFilter("secure", new SecurityFilter(engine)).addMappingForUrlPatterns(null, false, "/*");
```

```js
app.use(express.json({ limit: '1mb' }));
app.use(securityMiddleware({
  cors: new CorsPolicy({ allowOrigins: ['https://app.example.com'], allowCredentials: true }),
  rateLimiter: RateLimiter.perMinute(300),
  onEvent: (event) => siem.send(event),
}));
app.post('/login', rateLimit(RateLimiter.perMinute(10)), loginHandler);    // stricter limit for one route
app.get('/go', (req, res) => res.redirect(safeRedirect(req.query.next, '/', ['accounts.example.com'])));
```

The rate-limit key is the client address. Behind a reverse proxy, make sure that's the real
client address, by configuring Express `trust proxy` or the servlet container's
`RemoteIpValve` / `server.forward-headers-strategy` for your proxy only. Otherwise every client
can choose its own key with `X-Forwarded-For`.

## Developer tools: catch it while coding

The runtime filter catches attacks in production. These tools catch the **vulnerable code**
earlier, while it's being written, and let a developer attack their own app locally before
deploying. Java and JavaScript ship the same CLI with the same rules (`devtools/scan-rules.txt`)
and payloads (`devtools/probe-payloads.txt`).

| When | Tool | What it does |
|---|---|---|
| While editing | `secure scan` in the IDE | Flags vulnerable code at `file:line` with the fix; VS Code shows it in the Problems panel |
| Before compiling / committing | git pre-commit hook | Blocks the commit if it adds HIGH findings |
| Before packaging / deploying | unit test or CI step | `mvn test` / `npm test` / CI fails on HIGH findings; SARIF for code-scanning UIs |
| Manual testing, local server | `secure probe` | Fires attack payloads at your own running app and reports what got through |
| Investigating a blocked request | `secure check` | Shows how the filter decodes a value and which rules match |
| Checking object-level authorization | `secure idor` | Fetches one object as its owner, as another user and logged out; reports if anyone but the owner gets it |

```bash
# Java (any JDK 8+). The jar has no dependencies: download secure-core-0.1.0.jar from the
# GitHub release, or from Maven Central:
curl -LO https://repo1.maven.org/maven2/io/github/wahindra/secure-core/0.1.0/secure-core-0.1.0.jar
java -jar secure-core-0.1.0.jar scan src/
java -jar secure-core-0.1.0.jar check "1;SELECT pg_sleep(5)--"
java -jar secure-core-0.1.0.jar probe "http://localhost:8080/api/orders?id=FUZZ"

# Node (npm install --save-dev @wahindra/secure, or run without installing: npx @wahindra/secure scan src/)
npx secure scan src/
npx secure check "1;SELECT pg_sleep(5)--"
npx secure probe "http://localhost:3000/search?q=FUZZ"
```

Exit codes are `0` ok, `1` findings, `2` usage error, so every command can gate a script.

### 1. `secure scan`: find vulnerable code

55 rules cover Java/Kotlin/Groovy/Scala, JavaScript/TypeScript, templates (Thymeleaf, JSP, Vue,
Handlebars, EJS, Nunjucks, Twig, FreeMarker) and configuration (`.properties`, `.yml`, `.env`).
Each finding names the OWASP category and the guard in this library that fixes it:

```
src/main/java/com/acme/OrderDao.java:42:22: HIGH SQL_STRING_CONCAT [A05:2025 Injection] SQL statement built by string concatenation
    String sql = "SELECT * FROM orders WHERE id = " + id;
    fix: Use a PreparedStatement / parameterized query with ? (or $1) placeholders. Identifiers such as ORDER BY columns cannot be parameters: use SafeSql.allowlisted(...) or SafeSql.mapped(...).
1 finding(s) (1 HIGH, 0 MEDIUM, 0 LOW) in 128 file(s), 55 rules.
```

| Area | Rules (run `secure rules` for the full list) |
|---|---|
| A05 Injection | SQL concatenation / `String.format` / template literals / raw ORM queries, NoSQL operator injection, `Runtime.exec`, `sh -c`, `child_process.exec`, `shell: true`, `eval`/`new Function`, script engines / SpEL / OGNL, regex from input, XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`, `th:utext`, `v-html`, `{{{ }}}`, JSP scriptlets, servlet/Express echo) |
| A01 Broken Access Control | path traversal (Java + Node), Zip Slip, open redirect, SSRF (Java + Node), `anyRequest().permitAll()`, CSRF disabled, CORS `*`, user identity taken from the request instead of the token (`@RequestParam userId`, `req.query.userId`, `X-User-Id`), IDOR hint (`findById` with no ownership check in the file), mass assignment / prototype pollution |
| A04 / A07 Crypto & auth | MD5/SHA-1, fast hash for passwords, DES/RC4/ECB (and plain `"AES"`), `Random`/`Math.random` for tokens, hard-coded secrets, cloud keys and private keys, TLS validation disabled, insecure cookie flags, unverified JWTs / `alg: none` |
| A08 Integrity | `ObjectInputStream`, `XMLDecoder`, Jackson default typing, SnakeYAML `new Yaml()`, `node-serialize`, XXE-prone XML parsers |
| A09 / A10 Logging & errors | request data in logs, secrets in logs, exception details in responses, `printStackTrace()`, empty `catch` |
| A02 Config | stack traces in error responses, all actuator endpoints exposed, H2 console / debug on, insecure session cookies, secrets in config, CORS `*` |

Options: `--fail-on high|medium|low|none` (default `high`), `--format text|json|sarif`,
`--output FILE`, `--exclude DIR`, `--no-fix`. `node_modules`, `target`, `build`, `dist`, `.git`
and similar folders are skipped.

**Suppressing a reviewed finding.** Put a comment on the same line or the line above, with the
reason. Suppressions are visible in code review:

```java
// secure-scan:ignore SQL_STRING_CONCAT -- col comes from SafeSql.allowlisted(...)
String sql = "SELECT * FROM orders ORDER BY " + col;
```

**In the IDE:**

- **VS Code:** copy `devtools/ide/vscode-tasks.json` to `.vscode/tasks.json`, then run
  *Terminal → Run Task → secure: scan*. Findings appear in the Problems panel with squiggles
  (HIGH = error, MEDIUM = warning, LOW = info). The file also has tasks for `check` and `probe`.
- **IntelliJ IDEA:** *Settings → Tools → External Tools → +*. Program `java`, arguments
  `-jar /path/to/secure-core.jar scan $ProjectFileDir$/src --no-fix`. The `path:line:col` output
  is clickable in the Run window. Bind it to a shortcut to scan on demand.
- **Any SARIF viewer** (VS Code SARIF Viewer, Qodana, GitHub code scanning):
  `secure scan --format sarif --output secure.sarif`.

### 2. Pre-commit hook: block it before it's committed

```bash
cp devtools/hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# or share it with the team:  git config core.hooksPath devtools/hooks
```

The hook scans only the staged files. It uses the first scanner it finds: a full command in
`$SECURE_SCAN` (e.g. `SECURE_SCAN='java -jar "C:/tools/secure-core.jar" scan'`),
`./node_modules/.bin/secure`, `secure` on the `PATH`, or the jar at `$SECURE_JAR`.
`SECURE_FAIL_ON=medium` makes it stricter. If the scanner itself cannot run, the commit is
blocked with a clear message rather than silently allowed. `git commit --no-verify` is the
deliberate escape hatch.

```
src\Dao.java:2:36: HIGH SQL_STRING_CONCAT [A05:2025 Injection] SQL statement built by string concatenation
1 finding(s) (1 HIGH, 0 MEDIUM, 0 LOW) in 1 file(s), 55 rules.

secure-scan: commit blocked by high findings above. Fix them, or suppress a reviewed one with
  // secure-scan:ignore RULE_ID -- reason
```

### 3. Test / CI gate: block it before it's deployed

Java, as a normal JUnit test, so `mvn test` fails before `package` or `deploy`:

```java
import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.SourceScanner;

class SecurityScanTest {
    @Test
    void noHighSeverityFindings() throws IOException {
        SourceScanner.assertNoFindings(Severity.HIGH, Paths.get("src/main"));
    }
}
```

Node, with the built-in test runner:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SourceScanner, atLeast, toText } from '@wahindra/secure/devtools';

test('no HIGH security findings', () => {
  const report = new SourceScanner().scan('src');
  assert.deepEqual(atLeast(report.findings, 'HIGH').map((f) => `${f.file}:${f.line} ${f.rule.id}`), [], toText(report));
});
```

CI (any system): run `secure scan src --format sarif --output secure.sarif` and fail on exit
code 1. Upload the SARIF file to your code-scanning view if you have one.

### 4. `secure probe`: attack your own app before deploying

Start the app locally, put `FUZZ` where user input goes, and the probe sends 44
non-destructive payloads. It reports the responses that show the attack worked:

| Check | Reported when |
|---|---|
| `sqli-error` | a database error appears in the response |
| `sqli-time` / `cmd-time` | the response is ≥ 2.5 s slower than the baseline (payloads sleep 3 s, e.g. `pg_sleep(3)`) |
| `sqli-true` / `sqli-false` | `OR 1=1` and `AND 1=2` produce different responses (boolean-based blind) |
| `xss` | the payload comes back unencoded |
| `path` | `/etc/passwd` or `win.ini` content is returned |
| `cmd` | `id` command output is returned |
| `ssti` | `{{31337*3}}` comes back as `94011` |
| any | HTTP 5xx with a stack trace in the body (A10) |

```bash
secure probe "http://localhost:8080/api/orders?id=FUZZ"
secure probe "http://localhost:8080/api/search" -X POST -d '{"q":"FUZZ"}' -H "Authorization: Bearer $TOKEN"
secure probe "http://localhost:3000/files?name=FUZZ" --only path,cmd
```

Real output against a deliberately vulnerable local endpoint:

```
baseline: HTTP 200, 20 bytes, 86 ms
HIGH    sqli-error HTTP 500      3 ms  '                                              database error in response: SQL injection likely
ok      sqli-error HTTP 200      3 ms  "                                              no sign of vulnerability
HIGH    sqli-error HTTP 500      2 ms  1' AND 1=CAST((SELECT version()) AS int)--     database error in response: SQL injection likely
HIGH    sqli-error HTTP 500      3 ms  1';DO $$BEGIN RAISE EXCEPTION 'secprobe'; E... database error in response: SQL injection likely
HIGH    xss        HTTP 200      2 ms  <script>alert(31337)</script>                  payload reflected unencoded: XSS
HIGH    xss        HTTP 200      2 ms  "><img src=x onerror=alert(31337)>             payload reflected unencoded: XSS
...
13 payloads sent: 8 HIGH, 0 MEDIUM, 0 blocked by the secure filter.
```

If the secure filter/middleware is running in block mode, the probe shows `blocked by secure filter`.
To check the **code itself**, run the probe with the filter in monitor mode or disabled. Otherwise
you are only testing the filter.

**Safety:** the probe only targets loopback and private-network addresses (localhost,
10.x, 192.168.x, ...). `--allow-remote` is required for anything else. Use it only on systems
you own or are authorized to test. Payloads never write or delete data, but they do hit your
endpoints, so point the probe at a local or test database.

### 5. `secure check`: why was this request blocked?

```
$ secure check "1';DO \$\$BEGIN RAISE EXCEP/**/TION '%', (SELECT version()); END\$\$;--"
input     : 1';DO $$BEGIN RAISE EXCEP/**/TION '%', (SELECT version()); END$$;--
decoded   : 1';do $$begin raise excep/**/tion '%', (select version()); end$$;--
stripped  : 1';do $$begin raise excep tion '%', (select version()); end$$;--
verdict   : MALICIOUS (would be blocked)  score=36 (block at 6)
  MEDIUM SQLI_VERSION_CALL            version() call  [A05:2025]
  HIGH   SQLI_RAISE_EXCEPTION_SPLIT   RAISE EXCEPTION split by spaces or comments  [A05:2025]
  HIGH   SQLI_PG_DO_BLOCK             PostgreSQL anonymous DO $$ block  [A05:2025]
  HIGH   SQLI_STACKED_QUERY           Stacked (piggy-backed) statement  [A05:2025]
  MEDIUM SQLI_INLINE_COMMENT          Inline comment used as keyword separator  [A05:2025]

$ secure check "O'Brien"
input     : O'Brien
decoded   : o'brien
verdict   : clean  score=0 (block at 6)
```

Use it to tune false positives: when a legitimate value is blocked, add it to
`test-vectors/*-benign.txt` and adjust the rule.

### What the scanner cannot do

It is a fast, line-based pattern scanner, not a full SAST tool. It doesn't follow data across
lines or files, so `String sql = base + where;` built over several statements, or input that
reaches a sink through helper methods, can be missed. A pattern can also match safe code;
that's what reviewed suppressions are for. Use it as the always-on first check, and add a
data-flow SAST (Semgrep, CodeQL, SonarQube) in CI for depth.

## End-to-end check in your own app

Before deploying, attack your running app the way the library's own CI does. With the app
running locally, plus tokens (or cookies) for two ordinary users:

```bash
# 1. Injection, XSS, traversal, command and template injection against each input
secure probe "http://localhost:8080/api/search?q=FUZZ"
secure probe "http://localhost:8080/api/orders" -X POST -d '{"note":"FUZZ"}' -H "Authorization: Bearer $TOKEN_ALICE"

# 2. Object-level authorization on each endpoint that returns one user's data
secure idor http://localhost:8080/api/orders/42 \
  --as-owner "Authorization: Bearer $TOKEN_ALICE" --as-other "Authorization: Bearer $TOKEN_BOB" --marker "alice@"

# 3. The code itself
secure scan src/
```

Exit code 0 from all three means nothing was found. This repository runs exactly this against
a real Spring Boot app in `secure-spring-boot-starter/src/test/.../demo/`, on Spring Boot 3.5
and 4.2 in CI:

| Check | With the starter | Starter switched off (control) |
|---|---|---|
| `secure probe` on a deliberately vulnerable `/api/search` | 0 findings, 30+ payloads blocked | reflected XSS found (HIGH) |
| JSON body attack `{"q":"' OR 1=1--"}` | 400; clean bodies reach the controller unchanged | n/a |
| `secure idor` on the correct `/api/orders/{id}` | 0 findings (other user 403, anonymous 401) | n/a |
| `secure idor` on the broken `/api/vuln/orders/{id}` | HIGH: the other user can read it | n/a |
| Rate limit 3/min | 4th request 429 with `Retry-After` | n/a |
| CORS preflight, open redirect, security headers | allowed origin 204, other 403; `next=https://evil` goes to `/` | n/a |

To check the code itself rather than the filter, run the probe with `secure.mode=monitor` or the
starter disabled. Then you see what the application would do without the safety net.

## Coverage

### OWASP Top 10

The reference is the current **OWASP Top 10:2025**, the edition in force in 2026; OWASP has not
published a separate 2026 web-application list. The full mapping, with class and function names,
is in [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md).

| 2025 | Category | Covered by |
|---|---|---|
| A01 | Broken Access Control (incl. SSRF) | route policy, ownership/tenant/mass-assignment guards, identity from verified tokens, `secure idor`, path traversal guard + detector, CSRF, strict CORS, safe redirects, SSRF URL guard |
| A02 | Security Misconfiguration | security headers, leaky-header list, filter/middleware, Spring Boot starter defaults |
| A03 | Software Supply Chain Failures | zero dependencies; run OWASP Dependency-Check / `npm audit` in CI (build-time concern) |
| A04 | Cryptographic Failures | PBKDF2 password hashing, secure tokens, constant-time compare, HMAC |
| A05 | Injection | SQLi / XSS / command / JNDI / EL / SSTI detectors, `SafeSql`, `SafeCommand`, output encoders |
| A06 | Insecure Design | API rate limiting, login throttling, deny-by-default, per-request inspection budget |
| A07 | Authentication Failures | password policy, login attempt limiter, password hashing |
| A08 | Software or Data Integrity Failures | deserialization allowlist (Java), webhook HMAC verification |
| A09 | Security Logging and Alerting Failures | security events for alerting (`SecurityEventListener` / `onEvent`), log sanitizer (CRLF, secret masking), incident logging |
| A10 | Mishandling of Exceptional Conditions | generic error bodies with incident ids, fail-closed filter/middleware |

### Detected attack families

The SQL injection rules target the PostgreSQL probes these apps are seeing, plus the MySQL,
MSSQL, Oracle and SQLite equivalents:

| Probe | Rule ids |
|---|---|
| `RAISE EXCEPTION` marker | `SQLI_RAISE_EXCEPTION`, `SQLI_RAISE_EXCEPTION_SPLIT`, `SQLI_PG_DO_BLOCK` |
| `pg_sleep` (stacked) | `SQLI_STACKED_QUERY`, `SQLI_PG_SLEEP`, `SQLI_PG_SLEEP_SPLIT` |
| `pg_sleep` (boolean-OR) | `SQLI_BOOLEAN_SUBQUERY`, `SQLI_PG_SLEEP` |
| `version()` CAST error | `SQLI_CAST_ERROR`, `SQLI_VERSION_CAST` |
| boolean `OR 1=1` / `1=2` | `SQLI_BOOLEAN_TAUTOLOGY` |
| `EXECUTE` dynamic marker | `SQLI_EXECUTE_DYNAMIC`, `SQLI_EXECUTE_DYNAMIC_SPLIT`, `SQLI_PG_DO_BLOCK` |
| UNION, error functions, catalog access, `COPY ... PROGRAM`, file reads, MSSQL procs, `admin'--` | 17 further `SQLI_*` rules (29 in total) |
| XSS | 8 `XSS_*` rules |
| OS command, JNDI/Log4Shell, EL/OGNL, SSTI | 9 `CMD_*` / `JNDI_*` / `EL_*` / `SSTI_*` rules |
| Path traversal / LFI | 6 `PATH_*` rules |

Before matching, input is decoded: repeated URL encoding, `%uXXXX`, overlong UTF-8, HTML entities,
full-width Unicode (NFKC), SQL comments (`pg_sl/**/eep`), MySQL `/*!50000 */` and whitespace tricks.
Rules run against three views of the input: decoded, comment-stripped, and "compact" (all
whitespace removed, which catches `pg_sl eep(` style splitting).

**Scoring:** one HIGH finding, or two MEDIUM findings in the same field, marks the input as
malicious. Findings never contain the input text, so they are safe to log.

**Test vectors** (shared by both languages, all must pass):

| File | Lines | Must be |
|---|---:|---|
| `sqli-malicious.txt` | 60 | detected |
| `sqli-benign.txt` | 27 | not flagged (`O'Brien`, `rock and roll`, `drop by anytime`...) |
| `xss-malicious.txt` / `xss-benign.txt` | 17 / 8 | detected / not flagged |
| `path-malicious.txt` / `path-benign.txt` | 16 / 6 | detected / not flagged |
| `cmd-malicious.txt` / `cmd-benign.txt` | 17 / 6 | detected / not flagged |

### Test and code coverage

| | Tests | Line coverage | Branch coverage |
|---|---:|---:|---:|
| Java `secure-core` (JaCoCo 0.8.16, JDK 21) | 372 passed, 1 skipped\* | 83.1% | 69.4% |
| JavaScript (`node --experimental-test-coverage`) | 82 passed | 92.6% | 82.5% |
| Java servlet filters (javax, jakarta) | 8 + 8 passed | not measured | not measured |
| Spring Boot starter, end-to-end (Boot 3.5 and 4.2) | 9 passed on each | not measured | not measured |

\* The symlink-escape test is skipped on Windows unless symlinks are permitted (admin rights or
Developer Mode). The JavaScript equivalent runs and passes.

<details>
<summary>Java coverage per package</summary>

| Package | Lines | Branches |
|---|---:|---:|
| `secure` (root) | 90.7% | 83.3% |
| `.access` | 86.6% | 73.0% |
| `.crypto` | 81.7% | 73.4% |
| `.detect` | 94.9% | 84.9% |
| `.devtools` (scanner, probe, idor, CLI) | 74.5% | 64.1% |
| `.errors` | 100.0% | 100.0% |
| `.injection` | 86.2% | 63.2% |
| `.integrity` | 91.3% | 78.9% |
| `.logging` | 89.3% | 75.0% |
| `.path` | 82.8% | 70.4% |
| `.ssrf` | 78.6% | 55.6% |
| `.web` (filter engine, rate limit, CORS, redirects, events) | 86.3% | 75.8% |

</details>

## Benchmark

**Setup:** AMD Ryzen 9 5900HX (8 cores / 16 threads), Windows 11, single thread. No JMH (to stay
dependency-free): each case warms up for 0.6 s, then runs 7 rounds of 0.3 s, and the table shows
the **median time per operation**. Treat the numbers as orders of magnitude; they will differ on
your hardware, and Linux file-system calls are much cheaper than Windows ones.

```bash
# Java (use ':' instead of ';' as the classpath separator on Linux/macOS)
cd java && mvn -pl secure-core test-compile
java -cp "secure-core/target/classes;secure-core/target/test-classes" io.github.wahindra.secure.bench.DetectorBenchmark

# JavaScript
cd js && npm run bench
```

### Results

| Case | Java 8 | Java 17 | Java 21 | Node 26 |
|---|---:|---:|---:|---:|
| inspect: short benign value (22 chars) | 1.4 µs | 1.3 µs | 1.2 µs | 4.0 µs |
| inspect: benign sentence (61 chars) | 8.0 µs | 8.7 µs | 8.2 µs | 6.2 µs |
| inspect: SQLi payload (`pg_sleep` stacked) | 8.2 µs | 8.8 µs | 9.0 µs | 5.2 µs |
| inspect: double-encoded SQLi | 7.6 µs | 7.4 µs | 7.6 µs | 9.4 µs |
| inspect: PG `DO $$` block with `RAISE EXCEPTION` | 19.1 µs | 20.4 µs | 20.9 µs | 8.6 µs |
| inspect: 4 KB benign text | 225 µs | 209 µs | 219 µs | 157 µs |
| inspect: 64 KB benign text (max inspected size) | 3.6 ms | 3.3 ms | 3.4 ms | 2.5 ms |
| SQLi detector only: `' OR 1=1--` | 1.7 µs | 1.6 µs | 1.7 µs | 2.0 µs |
| **HTTP request: 12 params + 3 headers** | **55 µs** | **56 µs** | **52 µs** | **102 µs** |
| ReDoS probe: 64 KB of `'` | 2.1 ms | 1.7 ms | 1.8 ms | 0.6 ms |
| ReDoS probe: 64 KB of `or 1=` | 4.1 ms | 3.1 ms | 3.2 ms | 1.7 ms |
| ReDoS probe: 64 KB of `<a ` | 3.8 ms | 3.6 ms | 3.8 ms | 1.9 ms |
| ReDoS probe: 64 KB of `/*` | 4.4 ms | 4.6 ms | 4.6 ms | 1.2 ms |
| ReDoS probe: 64 KB of `${` | 2.0 ms | 1.6 ms | 1.6 ms | 1.2 ms |
| ReDoS probe: 64 KB of `%25` | 8.3 ms | 6.9 ms | 6.9 ms | 3.8 ms |
| `PathTraversalGuard.resolve` (3 segments) | 325 µs | 329 µs | 329 µs | 190 µs |
| `RouteAccessPolicy.evaluate` | 1.8 µs | 1.3 µs | 1.3 µs | 1.5 µs |
| `Encode.forHtml` / `forHtml` (1 KB) | 8.5 µs | 8.3 µs | 6.5 µs | 22.5 µs |
| `PasswordHasher.hash` (600k iterations) | **1,438 ms** | 138 ms | 140 ms | 103 ms |

**What this means:**

- A typical request costs about **50–100 µs** of inspection on one core, so the filter is not the
  bottleneck for normal APIs. The cost grows linearly with the amount of input, at roughly
  50 µs per KB (Java), and a single value is inspected up to 64 KB.
- **ReDoS-resistant:** inputs designed to cause catastrophic regex backtracking stay in the low
  milliseconds. The test suites contain 13 such inputs per language that fail if any takes over 1 s.
- **Java 8 password hashing is about 10× slower** than on Java 17+ because of the JDK 8 PBKDF2
  implementation. At 600k iterations, one login takes about 1.4 s of CPU, which also makes the
  login endpoint an easy target for exhausting the server. On Java 8, rate-limit logins
  (`LoginAttemptLimiter`), hash on a bounded thread pool, and consider moving to Java 17+. Don't
  just lower the iteration count without understanding the trade-off.
- `PathTraversalGuard.resolve` is dominated by the operating system's real-path lookups, which
  are needed to catch symlink escapes; the string checks themselves take a few microseconds.

### Before and after the ReDoS fix

The first benchmark run found a ReDoS bug and a slow inner loop. Both are fixed: every rule now
has a literal prefilter (no regex runs unless its keywords are present), repeats that could
rescan the input from every position are bounded, and normalization skips work for plain ASCII.

| Case | Java 21 before | Java 21 after | Node 26 before | Node 26 after |
|---|---:|---:|---:|---:|
| 64 KB of `<a ` | **11,247 ms** | 3.8 ms | 421 ms | 1.9 ms |
| 64 KB of `${` | 356 ms | 1.6 ms | 29.9 ms | 1.2 ms |
| short benign value | 19.0 µs | 1.2 µs | 3.6 µs | 4.0 µs |
| 64 KB benign text | 64.0 ms | 3.4 ms | 2.1 ms | 2.5 ms |
| HTTP request, 12 params + 3 headers | 370 µs | 52 µs | 110 µs | 102 µs |

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and on every pull request:

| Job | What it checks |
|---|---|
| **Java** | `mvn verify` on Temurin 8, 11, 17, 21 and 25 (Linux) and 21 (Windows). On Java 17+ this includes the Spring Boot starter and its end-to-end tests (Spring Boot 3.5). Java 21 also produces the JaCoCo report (downloadable artifact `jacoco-report`). Surefire reports are uploaded when a job fails. |
| **Node** | `npm test` on Node 20, 22, 24 and 26 (Linux) and 24 (Windows). Node 24 also runs coverage, checks that the npm package contains the CLI and the shared rule files, type-checks the TypeScript definitions, and fails if npm would rewrite `package.json` at publish time. |
| **Spring Boot 4 starter** | The starter's end-to-end tests again, against Spring Boot 4.2 (`-Dspring-boot.version=4.2.0`). |
| **Security scan** | The repository scans itself with `secure scan`. Results appear under *Security → Code scanning* (SARIF), and the job fails on any HIGH finding. |
| **Java and JavaScript agree** | Both CLIs scan the shared fixtures, and `.github/scripts/compare-scanners.mjs` fails if their findings differ. |

`.github/dependabot.yml` opens weekly update PRs for Maven, npm and GitHub Actions. Updates
that would drop Java 8 support (JUnit 6, Jakarta Servlet 6) are excluded. Raise the minimum
Java version first if you want them.

`.github/workflows/release.yml` runs when a `vX.Y.Z` tag is pushed. It checks that the tag is
on `main`, runs the whole CI suite above, then publishes to Maven Central (signed, using
repository secrets) and to npm (trusted publishing: no token, provenance attached), and creates a
GitHub release with the CLI jar attached. See [RELEASING.md](RELEASING.md).

## Rolling it out

0. In development: install the pre-commit hook, add the scan test, and run
   `secure scan --fail-on none` once to see the existing backlog. Fix or suppress the HIGH ones
   first, then make the build fail on new HIGH findings.
1. Deploy the filter/middleware in **monitor** mode. Every suspicious request is logged with an
   incident id, the field and the rule ids, never the payload itself.
2. Review the logs for false positives. Add those inputs to `test-vectors/*-benign.txt` and
   adjust the rule in **both** languages; both suites must stay green.
3. Switch to **block** mode.
4. Fix the underlying code with the guards. The detectors don't make vulnerable code safe.

## Limitations

- Signature detection can be evaded by novel encodings. Treat it as a tripwire and a scanner
  filter, not as your protection against SQL injection or XSS.
- Request bodies: JSON bodies are inspected (up to `maxBodyBytes`, 1 MB by default). XML,
  multipart and other body types are not inspected; form bodies are, through the parameters.
  Keep the container's request-size limits (Tomcat `maxPostSize`, `express.json({ limit })`) in
  place too.
- Inspection is capped per request (2,000 values, 256 K characters, nesting depth 20 by default).
  A request over a cap counts as malicious. A legitimate API that sends bigger requests needs
  higher limits (`secure.inspection.*` or the builder), or the filter excluded from those
  routes.
- `RateLimiter` and `LoginAttemptLimiter` keep their state in memory, per instance. With several
  instances, divide the limits by the instance count, or apply the same rules in a shared store
  (Redis) or at the gateway.
- `LoginAttemptLimiter` keeps its state in memory. Use a shared store when running multiple instances.
  It tracks at most `maxTrackedKeys` keys (default 100,000). When full, it drops expired entries,
  then evicts the entry with the **fewest** live failures (oldest first), and active lockouts
  last. Unknown accounts are never blocked, so a flood can't lock real users out. To reset a
  victim holding *k* failures, an attacker must first fill the table with entries holding at
  least *k* failures each: at least *k* × 100,000 failed attempts to win back *k* guesses, i.e.
  one extra guess per 100,000 requests. Alert on a rising `evictionCount()` / `evictionCount`,
  and put a per-IP limiter in front so one source can't produce that volume. Use separate
  instances for accounts and IPs so flooding one cannot push entries out of the other.
- The Spring Boot starter supports servlet (Spring MVC) applications. WebFlux (reactive) apps
  can use `SecurityFilterEngine` directly, but have no auto-configuration yet.
- Supply chain (A03) is a build-time concern. Run `mvn org.owasp:dependency-check-maven:check`
  and `npm audit` in CI.
