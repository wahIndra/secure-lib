import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  HttpRequestInspector,
  RateLimiter,
  CorsPolicy,
  safeRedirect,
  securityEvent,
  emitSecurityEvent,
  SecurityEventType,
  LoginAttemptLimiter,
  OwaspCategory,
  AccessDeniedError,
  ClaimMappings,
} from '../src/index.js';
import { securityMiddleware, rateLimit, cors, currentUser, errorHandler } from '../src/express.js';

const quiet = { log() {}, info() {}, warn() {}, error() {} };

// ---------------------------------------------------------------- inspection budget

test('budget stops padding attacks and huge requests (same limits as Java)', () => {
  const small = new HttpRequestInspector({ maxInspectedChars: 1000, maxValues: 10 });
  const r = small.inspect({ query: { pad: 'a'.repeat(2000), q: "' OR 1=1--" } });
  assert.equal(r.malicious, true);
  assert.equal(r.budgetExceeded, true);
  assert.match(r.summary, /inspection-budget-exceeded/);
  const many = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`p${i}`, 'v']));
  assert.match(small.inspect({ query: many }).summary, /too-many-values/);
  assert.equal(new HttpRequestInspector().inspect({ query: many }).suspicious, false);

  const huge = Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`p${i}`, 'x'.repeat(65536)]));
  const start = performance.now();
  assert.equal(new HttpRequestInspector().inspect({ body: huge }).budgetExceeded, true);
  assert.ok(performance.now() - start < 1000, '500 x 64 KB must stop at the budget');
});

// ---------------------------------------------------------------- rate limiting

test('rate limiter: burst, refill, independent keys, bounded memory', () => {
  let now = 0;
  const rl = new RateLimiter({ capacity: 3, periodMs: 3000, now: () => now });
  assert.ok(rl.tryAcquire('ip-1').allowed);
  assert.ok(rl.tryAcquire('ip-1').allowed);
  const third = rl.tryAcquire('ip-1');
  assert.ok(third.allowed);
  assert.equal(third.remaining, 0);
  const denied = rl.tryAcquire('ip-1');
  assert.equal(denied.allowed, false);
  assert.equal(denied.headers['Retry-After'], '1');
  assert.ok(rl.tryAcquire('ip-2').allowed);
  now += 1000;
  assert.ok(rl.tryAcquire('ip-1').allowed);
  assert.equal(rl.tryAcquire('ip-1').allowed, false);

  const bounded = new RateLimiter({ capacity: 5, periodMs: 1000, maxKeys: 100 });
  for (let i = 0; i < 10_000; i++) bounded.tryAcquire(`k${i}`);
  assert.equal(bounded.trackedKeys, 100);
});

// ---------------------------------------------------------------- redirects

test('unsafe redirects fall back (same cases as Java)', () => {
  for (const t of [
    'https://evil.example', '//evil.example', '/\\evil.example', '\\\\evil.example', '/%2F%2Fevil.example', '/%5cevil.example',
    'javascript:alert(1)', 'data:text/html,x', 'https://accounts.example.com@evil.example',
    'https://evil.example/?https://accounts.example.com', '/ok\r\nSet-Cookie: x=1', 'http://accounts.example.com.evil.example',
    ' ', 'https:evil.example', null,
  ]) {
    assert.equal(safeRedirect(t, '/', ['accounts.example.com', '*.shop.example']), '/', JSON.stringify(t));
  }
  assert.equal(safeRedirect('/orders/42?tab=items', '/'), '/orders/42?tab=items');
  assert.equal(safeRedirect('https://accounts.example.com/profile', '/', ['accounts.example.com']), 'https://accounts.example.com/profile');
  assert.equal(safeRedirect('https://eu.shop.example/', '/', ['*.shop.example']), 'https://eu.shop.example/');
  assert.equal(safeRedirect('https://shop.example/', '/', ['*.shop.example']), '/');
});

// ---------------------------------------------------------------- CORS

const policy = new CorsPolicy({
  allowOrigins: ['https://app.example.com', 'https://*.admin.example.com'],
  allowMethods: ['GET', 'POST', 'DELETE'],
  allowCredentials: true,
});

test('CORS allows listed origins only (same cases as Java)', () => {
  const ok = policy.evaluate({ origin: 'https://app.example.com', method: 'GET' });
  assert.equal(ok.headers['Access-Control-Allow-Origin'], 'https://app.example.com');
  assert.equal(ok.headers['Access-Control-Allow-Credentials'], 'true');
  assert.ok(policy.evaluate({ origin: 'https://eu.admin.example.com', method: 'GET' }).allowed);
  for (const bad of ['https://evil.example', 'null', 'https://app.example.com.evil.example', 'https://admin.example.com',
    'http://app.example.com', 'https://app.example.com/path', 'https://evilapp.example.com']) {
    const r = policy.evaluate({ origin: bad, method: 'GET' });
    assert.equal(r.allowed, false, bad);
    assert.equal(r.headers['Access-Control-Allow-Origin'], undefined, bad);
  }
  const pre = policy.evaluate({ origin: 'https://app.example.com', method: 'OPTIONS', requestMethod: 'DELETE', requestHeaders: 'content-type, authorization' });
  assert.ok(pre.preflight && pre.allowed);
  assert.equal(policy.evaluate({ origin: 'https://app.example.com', method: 'OPTIONS', requestMethod: 'PUT' }).allowed, false);
  assert.equal(policy.evaluate({ origin: 'https://app.example.com', method: 'OPTIONS', requestMethod: 'GET', requestHeaders: 'x-evil' }).allowed, false);
  assert.throws(() => new CorsPolicy({ allowOrigins: ['*'], allowCredentials: true }));
});

// ---------------------------------------------------------------- events and lockout

test('security events are sanitized, and a broken listener never breaks the caller', () => {
  const e = securityEvent(SecurityEventType.ACCESS_DENIED, { path: '/api/orders/9\r\nforged', principalId: 'alice', category: OwaspCategory.BROKEN_ACCESS_CONTROL });
  assert.equal(e.owasp, 'A01:2025');
  assert.ok(!e.path.includes('\n'));
  let got;
  emitSecurityEvent(e, [() => { throw new Error('siem down'); }, (x) => { got = x; }], quiet);
  assert.equal(got, e);
});

test('login lockout emits an event', () => {
  const events = [];
  const l = new LoginAttemptLimiter({ maxFailures: 2 }).onLockout((e) => events.push(e));
  l.recordFailure('alice');
  assert.equal(events.length, 0);
  l.recordFailure('alice');
  assert.equal(events[0].type, 'LOGIN_LOCKED');
  assert.equal(events[0].principalId, 'alice');
});

// ---------------------------------------------------------------- Express middleware

function fakeRes() {
  return {
    headers: {}, statusCode: 200, body: undefined, headersSent: false,
    setHeader(k, v) { this.headers[k] = v; },
    end(b) { this.body = b; this.headersSent = true; },
  };
}
const run = (mw, req) => {
  const res = fakeRes();
  let next = false;
  mw({ method: 'GET', originalUrl: '/api', headers: {}, ip: '10.0.0.7', ...req }, res, () => { next = true; });
  return { res, next };
};

test('middleware: rate limit, CORS preflight and events in one pipeline', () => {
  const events = [];
  const mw = securityMiddleware({ logger: quiet, cors: policy, rateLimiter: new RateLimiter({ capacity: 2, periodMs: 60_000 }), onEvent: (e) => events.push(e) });
  assert.ok(run(mw, {}).next);
  assert.ok(run(mw, {}).next);
  const limited = run(mw, {});
  assert.equal(limited.res.statusCode, 429);
  assert.ok(limited.res.headers['Retry-After']);
  assert.equal(events.at(-1).type, 'RATE_LIMITED');

  const corsOnly = securityMiddleware({ logger: quiet, cors: policy, onEvent: (e) => events.push(e) });
  const pre = run(corsOnly, { method: 'OPTIONS', headers: { origin: 'https://app.example.com', 'access-control-request-method': 'POST' } });
  assert.equal(pre.res.statusCode, 204);
  assert.equal(pre.next, false);
  const denied = run(corsOnly, { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } });
  assert.equal(denied.res.statusCode, 403);
  assert.equal(events.at(-1).type, 'CORS_REJECTED');

  const block = run(securityMiddleware({ logger: quiet, onEvent: (e) => events.push(e) }), { query: { q: "' OR 1=1--" } });
  assert.equal(block.res.statusCode, 400);
  assert.equal(events.at(-1).type, 'REQUEST_BLOCKED');
  assert.ok(events.at(-1).ruleIds.includes('SQLI_BOOLEAN_TAUTOLOGY'));
});

test('standalone rateLimit() and cors() middlewares', () => {
  const rl = rateLimit(new RateLimiter({ capacity: 1, periodMs: 60_000 }), { logger: quiet });
  assert.ok(run(rl, {}).next);
  assert.equal(run(rl, {}).res.statusCode, 429);
  const c = cors(policy);
  assert.ok(run(c, { headers: { origin: 'https://app.example.com' } }).next);
  assert.equal(run(c, { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'GET' } }).res.statusCode, 403);
});

test('currentUser() builds req.user from verified claims; errorHandler reports ACCESS_DENIED', () => {
  const mw = currentUser(ClaimMappings.keycloak({ clientId: 'orders-api' }));
  const req = { auth: { payload: { sub: 'alice', realm_access: { roles: ['user'] } } } };
  let nextCalled = false;
  mw(req, fakeRes(), () => { nextCalled = true; });
  assert.ok(nextCalled);
  assert.equal(req.user.id, 'alice');
  const noSub = fakeRes();
  mw({ auth: { payload: {} } }, noSub, () => {});
  assert.equal(noSub.statusCode, 401);

  const events = [];
  const res = fakeRes();
  errorHandler({ logger: quiet, onEvent: (e) => events.push(e) })(new AccessDeniedError('caller does not own resource'), { method: 'GET', url: '/api/orders/9', user: { id: 'alice' } }, res, () => {});
  assert.equal(res.statusCode, 403);
  assert.equal(events[0].type, 'ACCESS_DENIED');
  assert.equal(events[0].principalId, 'alice');
});
