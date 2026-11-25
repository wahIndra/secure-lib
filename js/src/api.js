/**
 * API protection: rate limiting, strict CORS, safe redirects and security events. Same behaviour
 * as the Java classes in io.github.wahindra.secure.web.
 */
import crypto from 'node:crypto';
import { sanitizeForLog } from './log.js';

// ---------------------------------------------------------------- rate limiting

/**
 * Token-bucket rate limiting per key (client IP, user id, API key...). Each key may make
 * `capacity` requests in a burst, refilled at `capacity / periodMs`. Memory is bounded: the least
 * recently seen key is forgotten first, which only gives that key a fresh bucket.
 *
 * Use the real client address. Behind a proxy, configure Express `trust proxy` for your proxy
 * only; otherwise clients choose their own key with `X-Forwarded-For`.
 */
export class RateLimiter {
  #buckets = new Map();

  constructor({ capacity, periodMs, maxKeys = 100_000, now = Date.now } = {}) {
    if (!(capacity >= 1) || !(periodMs > 0) || !(maxKeys >= 1)) throw new RangeError('capacity, periodMs and maxKeys must be positive');
    Object.assign(this, { capacity, periodMs, maxKeys, now });
    this.tokensPerMs = capacity / periodMs;
  }

  static perSecond(requests) {
    return new RateLimiter({ capacity: requests, periodMs: 1000 });
  }

  static perMinute(requests) {
    return new RateLimiter({ capacity: requests, periodMs: 60_000 });
  }

  /** @returns {{allowed: boolean, limit: number, remaining: number, retryAfterMs: number, resetMs: number, headers: object}} */
  tryAcquire(key) {
    const now = this.now();
    const k = key == null ? '' : String(key);
    let b = this.#buckets.get(k);
    if (b) {
      this.#buckets.delete(k); // re-insert below: Map order is least recently used first
      if (now > b.updated) {
        b.tokens = Math.min(this.capacity, b.tokens + (now - b.updated) * this.tokensPerMs);
        b.updated = now;
      }
    } else {
      b = { tokens: this.capacity, updated: now };
      if (this.#buckets.size >= this.maxKeys) this.#buckets.delete(this.#buckets.keys().next().value);
    }
    this.#buckets.set(k, b);
    const allowed = b.tokens >= 1;
    if (allowed) b.tokens -= 1;
    const resetMs = Math.ceil((this.capacity - b.tokens) / this.tokensPerMs);
    const retryAfterMs = allowed ? 0 : Math.ceil((1 - b.tokens) / this.tokensPerMs);
    const remaining = allowed ? Math.floor(b.tokens) : 0;
    const headers = {
      'RateLimit-Limit': String(this.capacity),
      'RateLimit-Remaining': String(remaining),
      'RateLimit-Reset': String(Math.ceil(resetMs / 1000)),
    };
    if (!allowed) headers['Retry-After'] = String(Math.ceil(retryAfterMs / 1000));
    return { allowed, limit: this.capacity, remaining, retryAfterMs, resetMs, headers };
  }

  get trackedKeys() {
    return this.#buckets.size;
  }
}

// ---------------------------------------------------------------- redirects

/**
 * Fixes open redirects: only relative paths on this site, or absolute http(s) URLs to listed hosts,
 * are accepted; anything else becomes `fallback`. Rejects //host, /\host and other backslashes,
 * other schemes, credentials in the URL, control characters and encoded leading slashes.
 */
export function isSafeRedirect(requested, allowedHosts = []) {
  if (typeof requested !== 'string') return false;
  const t = requested.trim();
  if (!t || t.length > 2048 || /[\u0000-\u001f\u007f\\]/.test(t)) return false;
  if (t.startsWith('/')) {
    const lower = t.toLowerCase();
    return !t.startsWith('//') && !lower.startsWith('/%2f') && !lower.startsWith('/%5c');
  }
  // Same rules as the Java URI check: an absolute http(s) URL with an authority part.
  if (!/^https?:\/\//i.test(t)) return false;
  let url;
  try {
    url = new URL(t);
  } catch {
    return false;
  }
  if (url.username || url.password || !url.hostname) return false;
  const host = url.hostname.toLowerCase();
  return allowedHosts.some((a) => {
    const h = a.toLowerCase();
    return h.startsWith('*.') ? host.endsWith(h.slice(1)) && host.length > h.length - 1 : host === h;
  });
}

export function safeRedirect(requested, fallback = '/', allowedHosts = []) {
  return isSafeRedirect(requested, allowedHosts) ? requested.trim() : fallback;
}

// ---------------------------------------------------------------- CORS

/**
 * Strict CORS: only listed origins. Never reflects an arbitrary Origin, never allows `null`, and
 * refuses `*` together with credentials.
 */
export class CorsPolicy {
  constructor({
    allowOrigins,
    allowMethods = ['GET', 'HEAD', 'POST'],
    allowHeaders = ['Content-Type', 'Authorization'],
    exposeHeaders = [],
    allowCredentials = false,
    maxAgeSeconds = 600,
  } = {}) {
    if (!Array.isArray(allowOrigins) || !allowOrigins.length) throw new Error('list at least one allowed origin');
    const norm = allowOrigins.map((o) => o.trim().toLowerCase().replace(/\/$/, ''));
    this.anyOrigin = norm.includes('*');
    if (this.anyOrigin && allowCredentials) throw new Error('allowOrigins ["*"] cannot be combined with allowCredentials: true');
    this.exact = norm.filter((o) => o !== '*' && !o.includes('://*.'));
    this.wildcards = norm.filter((o) => o.includes('://*.')).map((o) => o.replace('://*.', '://'));
    this.methods = new Set(allowMethods.map((m) => m.trim().toUpperCase()));
    this.allowHeaders = new Set(allowHeaders.map((h) => h.trim().toLowerCase()));
    Object.assign(this, { exposeHeaders, allowCredentials, maxAgeSeconds });
  }

  isAllowedOrigin(origin) {
    if (typeof origin !== 'string') return false;
    const o = origin.trim().toLowerCase().replace(/\/$/, '');
    if (o === 'null' || !/^https?:\/\//.test(o)) return false;
    const rest = o.slice(o.indexOf('://') + 3);
    if (!rest || rest.includes('/') || rest.includes('@')) return false;
    if (this.anyOrigin || this.exact.includes(o)) return true;
    return this.wildcards.some((w) => {
      const scheme = w.slice(0, w.indexOf('://') + 3);
      const domain = w.slice(scheme.length);
      return o.startsWith(scheme) && rest.endsWith(`.${domain}`) && rest.length > domain.length + 1;
    });
  }

  /** @returns {{preflight: boolean, allowed: boolean, headers: object}} */
  evaluate({ origin, method, requestMethod, requestHeaders }) {
    const preflight = String(method).toUpperCase() === 'OPTIONS' && requestMethod != null;
    const headers = {};
    if (origin == null) return { preflight: false, allowed: true, headers };
    headers.Vary = preflight ? 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers' : 'Origin';
    if (!this.isAllowedOrigin(origin)) return { preflight, allowed: false, headers };
    headers['Access-Control-Allow-Origin'] = this.anyOrigin && !this.allowCredentials ? '*' : origin;
    if (this.allowCredentials) headers['Access-Control-Allow-Credentials'] = 'true';
    if (preflight) {
      const onlyVary = { Vary: headers.Vary };
      if (!this.methods.has(String(requestMethod).trim().toUpperCase())) return { preflight, allowed: false, headers: onlyVary };
      const asked = String(requestHeaders ?? '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
      if (asked.some((h) => !this.allowHeaders.has(h))) return { preflight, allowed: false, headers: onlyVary };
      headers['Access-Control-Allow-Methods'] = [...this.methods].join(', ');
      if (this.allowHeaders.size) headers['Access-Control-Allow-Headers'] = [...this.allowHeaders].join(', ');
      headers['Access-Control-Max-Age'] = String(this.maxAgeSeconds);
    } else if (this.exposeHeaders.length) {
      headers['Access-Control-Expose-Headers'] = this.exposeHeaders.join(', ');
    }
    return { preflight, allowed: true, headers };
  }
}

// ---------------------------------------------------------------- security events

export const SecurityEventType = Object.freeze({
  REQUEST_BLOCKED: 'REQUEST_BLOCKED',
  REQUEST_FLAGGED: 'REQUEST_FLAGGED',
  RATE_LIMITED: 'RATE_LIMITED',
  CORS_REJECTED: 'CORS_REJECTED',
  ACCESS_DENIED: 'ACCESS_DENIED',
  LOGIN_LOCKED: 'LOGIN_LOCKED',
  LOGIN_FAILED: 'LOGIN_FAILED',
  LOGIN_SUCCEEDED: 'LOGIN_SUCCEEDED',
  INSPECTION_ERROR: 'INSPECTION_ERROR',
});

const clean = (v, max) => (v == null ? undefined : sanitizeForLog(String(v), max));

/**
 * A security-relevant event for alerting and audit (A09). Text fields are sanitized and never
 * contain request payloads, so an event can be sent as-is to a SIEM, Slack or metrics.
 */
export function securityEvent(type, { incidentId = crypto.randomUUID(), method, path, remoteAddress, principalId, category, ruleIds = [], detail } = {}) {
  return Object.freeze({
    type,
    incidentId,
    timestamp: new Date().toISOString(),
    method: clean(method, 16),
    path: clean(path, 300),
    remoteAddress: clean(remoteAddress, 64),
    principalId: clean(principalId, 128),
    owasp: category?.id2025,
    category: category?.title,
    ruleIds: Object.freeze([...ruleIds]),
    detail: clean(detail, 1000),
  });
}

/** Calls each listener; a failing listener is reported to `logger` and never affects the request. */
export function emitSecurityEvent(event, listeners = [], logger = console) {
  const level = event.type === SecurityEventType.REQUEST_FLAGGED ? 'info' : 'warn';
  const line = `security-event type=${event.type} incident=${event.incidentId}`
    + `${event.method ? ` method=${event.method}` : ''}${event.path ? ` path=${event.path}` : ''}`
    + `${event.remoteAddress ? ` remote=${event.remoteAddress}` : ''}${event.principalId ? ` principal=${event.principalId}` : ''}`
    + `${event.ruleIds.length ? ` rules=[${event.ruleIds.join(', ')}]` : ''}${event.detail ? ` detail=${event.detail}` : ''}`;
  (logger[level] ?? logger.log).call(logger, line);
  for (const l of listeners) {
    try {
      l(event);
    } catch (e) {
      (logger.warn ?? logger.log).call(logger, `security event listener failed: ${e?.name ?? 'Error'}`);
    }
  }
}
