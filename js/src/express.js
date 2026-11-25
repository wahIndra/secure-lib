/**
 * Express / Connect middleware (no Express dependency; works with any (req, res, next) stack).
 *
 * @example
 * import express from 'express';
 * import { securityMiddleware, errorHandler } from '@wahindra/secure/express';
 * const app = express();
 * app.disable('x-powered-by');
 * app.use(express.json({ limit: '100kb' }));
 * app.use(securityMiddleware({
 *   mode: 'monitor',                                   // start in monitor, then switch to 'block'
 *   cors: new CorsPolicy({ allowOrigins: ['https://app.example.com'] }),
 *   rateLimiter: RateLimiter.perMinute(300),
 *   onEvent: (e) => siem.send(e),
 * }));
 * // ... routes ...
 * app.use(errorHandler());
 */
import { HttpRequestInspector } from './http.js';
import { logError, publicErrorBody } from './log.js';
import { securityHeaders } from './web.js';
import { AccessDeniedError, principalFromVerifiedClaims } from './access.js';
import { OwaspCategory, SecurityViolationError } from './owasp.js';
import { securityEvent, emitSecurityEvent, SecurityEventType } from './api.js';

const sendJson = (res, status, body) => {
  if (res.headersSent) return;
  res.statusCode = status;
  if (body == null) return res.end();
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  return res.end(JSON.stringify(body));
};

const eventBase = (req) => ({
  method: req.method,
  path: (req.originalUrl ?? req.url ?? '').split('?')[0],
  remoteAddress: req.ip ?? req.socket?.remoteAddress,
});

/**
 * The request's audit fields: user (from currentUser() / req.user), client address, method and
 * path. audit.record('order.refund', { ...auditFields(req), resource: 'order/' + id })
 */
export function auditFields(req, { getPrincipal = (r) => r.user } = {}) {
  const p = getPrincipal(req);
  return { ...eventBase(req), principalId: p?.id ?? undefined };
}

/**
 * Same pipeline as the Java SecurityFilterEngine, in this order: security headers; CORS
 * (preflights answered with 204/403); rate limit (429 with Retry-After); inspection of path,
 * query, parsed body and selected headers within a budget. In 'block' mode malicious requests get
 * a generic 400; in 'monitor' mode they are only reported. Every decision worth knowing about is
 * logged and passed to `onEvent` listeners. Mount after body parsers so JSON bodies are inspected.
 *
 * @param {object} [options]
 * @param {'block'|'monitor'} [options.mode]
 * @param {object|null} [options.headers] response headers, null to leave them alone
 * @param {HttpRequestInspector} [options.inspector]
 * @param {CorsPolicy} [options.cors]
 * @param {RateLimiter} [options.rateLimiter]
 * @param {(req) => string} [options.rateLimitKey] default: req.ip
 * @param {Array<(event) => void>|((event) => void)} [options.onEvent]
 */
export function securityMiddleware({
  mode = 'block',
  headers = securityHeaders(),
  inspector = new HttpRequestInspector(),
  cors,
  rateLimiter,
  rateLimitKey = (req) => req.ip ?? req.socket?.remoteAddress,
  onEvent = [],
  logger = console,
  failOpen = false,
} = {}) {
  if (mode !== 'block' && mode !== 'monitor') throw new Error("mode must be 'block' or 'monitor'");
  const listeners = typeof onEvent === 'function' ? [onEvent] : onEvent;
  const emit = (type, req, extra) => {
    const event = securityEvent(type, { ...eventBase(req), ...extra });
    emitSecurityEvent(event, listeners, logger);
    return event.incidentId;
  };
  return function secure(req, res, next) {
    if (headers) {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    }

    if (cors) {
      const c = cors.evaluate({
        origin: req.headers.origin,
        method: req.method,
        requestMethod: req.headers['access-control-request-method'],
        requestHeaders: req.headers['access-control-request-headers'],
      });
      for (const [k, v] of Object.entries(c.headers)) res.setHeader(k, v);
      if (c.preflight) {
        if (c.allowed) return sendJson(res, 204, null);
        const id = emit(SecurityEventType.CORS_REJECTED, req, {
          category: OwaspCategory.SECURITY_MISCONFIGURATION, detail: `origin not allowed: ${req.headers.origin}`,
        });
        return sendJson(res, 403, { error: 'cors_rejected', incidentId: id });
      }
    }

    if (rateLimiter) {
      const d = rateLimiter.tryAcquire(rateLimitKey(req));
      for (const [k, v] of Object.entries(d.headers)) res.setHeader(k, v);
      if (!d.allowed) {
        const id = emit(SecurityEventType.RATE_LIMITED, req, {
          category: OwaspCategory.INSECURE_DESIGN, detail: `limit ${d.limit}, retry after ${d.headers['Retry-After']} s`,
        });
        return sendJson(res, 429, { error: 'rate_limited', incidentId: id });
      }
    }

    let report;
    try {
      report = inspector.inspect({ path: req.originalUrl ?? req.url, query: req.query, body: req.body, headers: req.headers });
    } catch (err) {
      const id = logError(logger, err, 'request inspection failed');
      emitSecurityEvent(securityEvent(SecurityEventType.INSPECTION_ERROR, { ...eventBase(req), incidentId: id, detail: err?.name }), listeners, logger);
      if (failOpen) return next();
      return sendJson(res, 400, { error: 'request_rejected', incidentId: id });
    }
    if (report.suspicious) {
      const block = mode === 'block' && report.malicious;
      const id = emit(block ? SecurityEventType.REQUEST_BLOCKED : SecurityEventType.REQUEST_FLAGGED, req, {
        category: report.findings[0]?.category ?? OwaspCategory.INSECURE_DESIGN,
        ruleIds: report.findings.map((f) => f.ruleId),
        detail: report.summary,
      });
      if (block) return sendJson(res, 400, { error: 'request_rejected', incidentId: id });
    }
    return next();
  };
}

/** Rate limiting on its own, e.g. a stricter limit for one route: `app.post('/login', rateLimit(RateLimiter.perMinute(10)), ...)`. */
export function rateLimit(rateLimiter, { key = (req) => req.ip ?? req.socket?.remoteAddress, onEvent = [], logger = console } = {}) {
  const listeners = typeof onEvent === 'function' ? [onEvent] : onEvent;
  return function limit(req, res, next) {
    const d = rateLimiter.tryAcquire(key(req));
    for (const [k, v] of Object.entries(d.headers)) res.setHeader(k, v);
    if (d.allowed) return next();
    const event = securityEvent(SecurityEventType.RATE_LIMITED, { ...eventBase(req), category: OwaspCategory.INSECURE_DESIGN });
    emitSecurityEvent(event, listeners, logger);
    return sendJson(res, 429, { error: 'rate_limited', incidentId: event.incidentId });
  };
}

/** Strict CORS on its own: `app.use(cors(new CorsPolicy({ allowOrigins: ['https://app.example.com'] })))`. */
export function cors(policy) {
  return function applyCors(req, res, next) {
    const c = policy.evaluate({
      origin: req.headers.origin,
      method: req.method,
      requestMethod: req.headers['access-control-request-method'],
      requestHeaders: req.headers['access-control-request-headers'],
    });
    for (const [k, v] of Object.entries(c.headers)) res.setHeader(k, v);
    if (!c.preflight) return next();
    return c.allowed ? sendJson(res, 204, null) : sendJson(res, 403, { error: 'cors_rejected' });
  };
}

/**
 * Builds `req.user` from an ALREADY VERIFIED token's claims, e.g. after express-oauth2-jwt-bearer
 * (`req.auth.payload`) or your own jose `jwtVerify` step. Responds 401 when there is no subject.
 * @param {(req) => object|undefined} getClaims
 */
export function currentUser(mapping, { getClaims = (req) => req.auth?.payload ?? req.auth } = {}) {
  return function setUser(req, res, next) {
    try {
      req.user = principalFromVerifiedClaims(getClaims(req), mapping);
      return next();
    } catch (e) {
      if (e instanceof AccessDeniedError) return sendJson(res, 401, { error: 'unauthenticated' });
      throw e;
    }
  };
}

/**
 * Final error handler: AccessDeniedError becomes 401/403, other SecurityViolationErrors 400,
 * everything else a generic 500 with an incident id. Stack traces never reach the client.
 */
export function errorHandler({ logger = console, onEvent = [] } = {}) {
  const listeners = typeof onEvent === 'function' ? [onEvent] : onEvent;
  // Express recognizes error handlers by their four parameters.
  // eslint-disable-next-line no-unused-vars
  return function secureErrorHandler(err, req, res, next) {
    const id = logError(logger, err, `${req.method} ${req.originalUrl ?? req.url}`);
    if (err instanceof AccessDeniedError) {
      emitSecurityEvent(securityEvent(SecurityEventType.ACCESS_DENIED, {
        ...eventBase(req), incidentId: id, principalId: req.user?.id, category: OwaspCategory.BROKEN_ACCESS_CONTROL, detail: err.message,
      }), listeners, logger);
    }
    if (res.headersSent) return;
    let status = 500;
    if (err instanceof AccessDeniedError) status = err.unauthenticated ? 401 : 403;
    else if (err instanceof SecurityViolationError) status = 400;
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(publicErrorBody(id)));
  };
}

/** Enforces a RouteAccessPolicy. `getPrincipal(req)` defaults to `req.user`. */
export function routePolicy(policy, { getPrincipal = (req) => req.user } = {}) {
  return function enforceRoutePolicy(req, res, next) {
    const d = policy.evaluate(req.method, req.originalUrl ?? req.url, getPrincipal(req));
    if (d.allowed) return next();
    res.statusCode = d.unauthenticated ? 401 : 403;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: d.unauthenticated ? 'unauthenticated' : 'forbidden' }));
  };
}

/** Rejects state-changing requests without a valid CSRF token (header or `_csrf` field). */
export function csrfProtection(csrfService, { getSessionId = (req) => req.sessionID, headerName = 'x-csrf-token' } = {}) {
  return function verifyCsrf(req, res, next) {
    if (!csrfService.constructor.requiresToken(req.method)) return next();
    const token = req.headers[headerName] ?? req.body?._csrf;
    if (csrfService.verify(getSessionId(req), token)) return next();
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'invalid_csrf_token' }));
  };
}
