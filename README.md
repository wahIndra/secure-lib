# secure-lib

[![CI](https://github.com/wahIndra/secure-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/wahIndra/secure-lib/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Java 8+](https://img.shields.io/badge/java-8%2B-orange)
![Node 20+](https://img.shields.io/badge/node-20%2B-green)

OWASP Top 10 prevention helpers for **Java 8+** and **Node.js 20+**, with zero runtime dependencies.

```bash
git clone https://github.com/wahIndra/secure-lib.git
cd secure-lib
(cd java && mvn install)   # Java: jars in ~/.m2, CLI jar in java/secure-core/target/
(cd js && npm test)        # Node: no dependencies to install
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
- [Developer tools: catch it while coding](#developer-tools-catch-it-while-coding)
- [Coverage](#coverage)
- [Benchmark](#benchmark)
- [Continuous integration](#continuous-integration)
- [Rolling it out](#rolling-it-out)
- [Limitations](#limitations)

## Layout

```
java/                     Maven multi-module, compiled with --release 8
  secure-core/            detectors and guards (no dependencies)
  secure-servlet-javax/   Filter for javax.servlet  (Java EE 8, Spring Boot 2, Tomcat 9)
  secure-servlet-jakarta/ Filter for jakarta.servlet (Jakarta EE 9+, Spring Boot 3, Tomcat 10+)
js/                       ESM package with TypeScript types and Express middleware
  bin/secure.js           developer CLI (npx secure scan | check | probe)
  bench/                  benchmark script
devtools/                 shared by both languages
  scan-rules.txt          54 source-code rules for `secure scan`
  probe-payloads.txt      payloads for `secure probe`
  hooks/pre-commit        git hook that blocks commits with HIGH findings
  ide/vscode-tasks.json   VS Code tasks with a problem matcher (findings in the Problems panel)
test-vectors/             shared payloads, crypto fixtures and scanner fixtures (scan/vulnerable, scan/safe)
docs/OWASP-MAPPING.md     what covers each Top 10 category
.github/
  workflows/ci.yml        build + test matrix, self-scan, Java/JS parity check
  dependabot.yml          weekly Maven, npm and GitHub Actions updates
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

The library uses no reflection and no JDK internals, so the Java 17+ module encapsulation does
not affect it.

## How to use: Java

### Build

```bash
cd java
mvn install                 # JDK 8 or newer
mvn -Pcoverage verify       # same, plus a JaCoCo report in secure-core/target/site/jacoco/
```

```xml
<!-- Spring Boot 3 / Jakarta EE 9+ -->
<dependency>
  <groupId>io.github.wahindra</groupId>
  <artifactId>secure-servlet-jakarta</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
<!-- Spring Boot 2 / Java EE: secure-servlet-javax. Guards only, no servlet: secure-core. -->
```

### 1. Request filter (detection + security headers)

Spring Boot 3 (on Spring Boot 2 import `io.github.wahindra.secure.servlet.javax.SecurityFilter`):

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

```bash
# Java (any JDK 8+). The jar has no dependencies; after `mvn install` it is at
# java/secure-core/target/secure-core-0.1.0-SNAPSHOT.jar (and in ~/.m2/repository/io/github/wahindra/secure-core/)
java -jar secure-core-0.1.0-SNAPSHOT.jar scan src/
java -jar secure-core-0.1.0-SNAPSHOT.jar check "1;SELECT pg_sleep(5)--"
java -jar secure-core-0.1.0-SNAPSHOT.jar probe "http://localhost:8080/api/orders?id=FUZZ"

# Node (npm install --save-dev @wahindra/secure)
npx secure scan src/
npx secure check "1;SELECT pg_sleep(5)--"
npx secure probe "http://localhost:3000/search?q=FUZZ"
```

Exit codes are `0` ok, `1` findings, `2` usage error, so every command can gate a script.

### 1. `secure scan`: find vulnerable code

54 rules cover Java/Kotlin/Groovy/Scala, JavaScript/TypeScript, templates (Thymeleaf, JSP, Vue,
Handlebars, EJS, Nunjucks, Twig, FreeMarker) and configuration (`.properties`, `.yml`, `.env`).
Each finding names the OWASP category and the guard in this library that fixes it:

```
src/main/java/com/acme/OrderDao.java:42:22: HIGH SQL_STRING_CONCAT [A05:2025 Injection] SQL statement built by string concatenation
    String sql = "SELECT * FROM orders WHERE id = " + id;
    fix: Use a PreparedStatement / parameterized query with ? (or $1) placeholders. Identifiers such as ORDER BY columns cannot be parameters: use SafeSql.allowlisted(...) or SafeSql.mapped(...).
1 finding(s) (1 HIGH, 0 MEDIUM, 0 LOW) in 128 file(s), 54 rules.
```

| Area | Rules (run `secure rules` for the full list) |
|---|---|
| A05 Injection | SQL concatenation / `String.format` / template literals / raw ORM queries, NoSQL operator injection, `Runtime.exec`, `sh -c`, `child_process.exec`, `shell: true`, `eval`/`new Function`, script engines / SpEL / OGNL, regex from input, XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`, `th:utext`, `v-html`, `{{{ }}}`, JSP scriptlets, servlet/Express echo) |
| A01 Broken Access Control | path traversal (Java + Node), Zip Slip, open redirect, SSRF (Java + Node), `anyRequest().permitAll()`, CSRF disabled, CORS `*`, IDOR hint (`findById` with no ownership check in the file), mass assignment / prototype pollution |
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
1 finding(s) (1 HIGH, 0 MEDIUM, 0 LOW) in 1 file(s), 54 rules.

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

## Coverage

### OWASP Top 10

The reference is the current **OWASP Top 10:2025**, the edition in force in 2026; OWASP has not
published a separate 2026 web-application list. The full mapping, with class and function names,
is in [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md).

| 2025 | Category | Covered by |
|---|---|---|
| A01 | Broken Access Control (incl. SSRF) | route policy, ownership/tenant/mass-assignment guards, path traversal guard + detector, CSRF, SSRF URL guard |
| A02 | Security Misconfiguration | security headers, leaky-header list, filter/middleware |
| A03 | Software Supply Chain Failures | zero dependencies; run OWASP Dependency-Check / `npm audit` in CI (build-time concern) |
| A04 | Cryptographic Failures | PBKDF2 password hashing, secure tokens, constant-time compare, HMAC |
| A05 | Injection | SQLi / XSS / command / JNDI / EL / SSTI detectors, `SafeSql`, `SafeCommand`, output encoders |
| A06 | Insecure Design | login throttling, deny-by-default, parameter-count cap |
| A07 | Authentication Failures | password policy, login attempt limiter, password hashing |
| A08 | Software or Data Integrity Failures | deserialization allowlist (Java), webhook HMAC verification |
| A09 | Security Logging and Alerting Failures | log sanitizer (CRLF, secret masking), incident logging |
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
| Java `secure-core` (JaCoCo 0.8.12, JDK 21) | 323 passed, 1 skipped\* | 83.4% | 68.8% |
| JavaScript (`node --experimental-test-coverage`) | 59 passed | 92.6% | 80.2% |
| Java servlet filter modules | none yet | not measured | not measured |

\* The symlink-escape test is skipped on Windows unless symlinks are permitted (admin rights or
Developer Mode). The JavaScript equivalent runs and passes.

<details>
<summary>Java coverage per package</summary>

| Package | Lines | Branches |
|---|---:|---:|
| `secure` (root) | 90.7% | 83.3% |
| `.access` | 79.3% | 70.2% |
| `.crypto` | 82.0% | 69.2% |
| `.detect` | 94.9% | 84.9% |
| `.devtools` (scanner, probe, CLI) | 78.8% | 69.0% |
| `.errors` | 100.0% | 100.0% |
| `.injection` | 86.2% | 63.2% |
| `.integrity` | 91.3% | 78.9% |
| `.logging` | 89.3% | 75.0% |
| `.path` | 82.8% | 70.4% |
| `.ssrf` | 78.6% | 55.6% |
| `.web` | 88.7% | 65.3% |

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
| **Java** | `mvn verify` on Temurin 8, 11, 17, 21 and 25 (Linux) and 21 (Windows). Java 21 also produces the JaCoCo report (downloadable artifact `jacoco-report`). Surefire reports are uploaded when a job fails. |
| **Node** | `npm test` on Node 20, 22, 24 and 26 (Linux) and 24 (Windows). Node 24 also runs coverage and checks that the npm package contains the CLI and the shared rule files. |
| **Security scan** | The repository scans itself with `secure scan`. Results appear under *Security → Code scanning* (SARIF), and the job fails on any HIGH finding. |
| **Java and JavaScript agree** | Both CLIs scan the shared fixtures, and `.github/scripts/compare-scanners.mjs` fails if their findings differ. |

`.github/dependabot.yml` opens weekly update PRs for Maven, npm and GitHub Actions. Updates
that would drop Java 8 support (JUnit 6, Jakarta Servlet 6) are excluded. Raise the minimum
Java version first if you want them.

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
- The servlet filter doesn't read request bodies (that would consume the stream). Form
  parameters are inspected through `getParameterMap()`, but JSON bodies are not. The Express
  middleware does inspect parsed JSON bodies.
- There is no per-request inspection budget yet: a request with the maximum 500 parameters of
  64 KB each would take roughly 1.7 s to inspect. Keep the container's request-size limits
  (e.g. Tomcat `maxPostSize`, `express.json({ limit })`) in place.
- `LoginAttemptLimiter` keeps its state in memory. Use a shared store when running multiple instances.
- The servlet filter modules have no automated tests yet; they have only been compiled.
- Supply chain (A03) is a build-time concern. Run `mvn org.owasp:dependency-check-maven:check`
  and `npm audit` in CI.
