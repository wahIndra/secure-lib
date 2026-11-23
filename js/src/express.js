/**
 * Express / Connect middleware (no Express dependency; works with any (req, res, next) stack).
 *
 * @example
 * import express from 'express';
 * import { securityMiddleware, errorHandler } from '@wahindra/secure/express';
 * const app = express();
 * app.disable('x-powered-by');
 * app.use(express.json({ limit: '100kb' }));
 * app.use(securityMiddleware({ mode: 'monitor' }));   // start in monitor, then switch to 'block'
 * // ... routes ...
 * app.use(errorHandler());
 */
import crypto from 'node:crypto';
import { HttpRequestInspector } from './http.js';
import { logError, publicErrorBody, sanitizeForLog } from './log.js';
import { securityHeaders } from './web.js';
import { AccessDeniedError } from './access.js';
import { SecurityViolationError } from './owasp.js';

/**
 * Adds security headers and inspects path, query, parsed body and selected headers.
 * In 'block' mode malicious requests get a generic 400; in 'monitor' mode they are only logged.
 * Mount after body parsers so JSON bodies are inspected.
 */
export function securityMiddleware({
  mode = 'block',
  headers = securityHeaders(),
  inspector = new HttpRequestInspector(),
  logger = console,
  failOpen = false,
} = {}) {
  if (mode !== 'block' && mode !== 'monitor') throw new Error("mode must be 'block' or 'monitor'");
  return function secure(req, res, next) {
    if (headers) {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    }
    let report;
    try {
      report = inspector.inspect({
        path: req.originalUrl ?? req.url,
        query: req.query,
        body: req.body,
        headers: req.headers,
      });
    } catch (err) {
      const id = logError(logger, err, 'request inspection failed');
      if (failOpen) return next();
      return reject(res, id);
    }
    if (report.suspicious) {
      const id = crypto.randomUUID();
      const block = mode === 'block' && report.malicious;
      const line =
        `security-middleware incident=${id} action=${block ? 'blocked' : 'allowed'}` +
        ` method=${sanitizeForLog(req.method, 16)} uri=${sanitizeForLog(req.originalUrl ?? req.url, 300)}` +
        ` remote=${sanitizeForLog(req.ip ?? req.socket?.remoteAddress, 64)} findings=${report.summary}`;
      (report.malicious ? logger.warn ?? logger.log : logger.info ?? logger.log).call(logger, line);
      if (block) return reject(res, id);
    }
    return next();
  };
}

function reject(res, incidentId) {
  if (res.headersSent) return;
  res.statusCode = 400;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({ error: 'request_rejected', incidentId }));
}

/**
 * Final error handler: AccessDeniedError becomes 401/403, other SecurityViolationErrors 400,
 * everything else a generic 500 with an incident id. Stack traces never reach the client.
 */
export function errorHandler({ logger = console } = {}) {
  // Express recognizes error handlers by their four parameters.
  // eslint-disable-next-line no-unused-vars
  return function secureErrorHandler(err, req, res, next) {
    const id = logError(logger, err, `${req.method} ${req.originalUrl ?? req.url}`);
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
