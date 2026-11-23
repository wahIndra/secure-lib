import { HmacSigner, randomToken } from './crypto.js';

export const DEFAULT_CSP =
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; " +
  "frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests";

/**
 * Recommended HTTP response headers (Security Misconfiguration). Pass overrides to change a
 * header, or `null` to drop one. `noStore: true` adds no-cache headers for authenticated pages.
 */
export function securityHeaders(overrides = {}, { noStore = false } = {}) {
  const h = {
    'Content-Security-Policy': DEFAULT_CSP,
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
  };
  if (noStore) {
    h['Cache-Control'] = 'no-store';
    h.Pragma = 'no-cache';
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v == null) delete h[k];
    else h[k] = v;
  }
  return h;
}

/** Headers that reveal server software; remove them (e.g. `app.disable('x-powered-by')`). */
export const LEAKY_HEADERS = Object.freeze(['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']);

/**
 * Stateless CSRF tokens bound to the session: `nonce.HMAC(sessionId|nonce)`. Same format as
 * the Java CsrfTokenService. Pair with SameSite=Lax (or Strict) session cookies.
 */
export class CsrfTokenService {
  constructor(secretKey) {
    this.signer = new HmacSigner(secretKey);
  }

  generate(sessionId) {
    if (!sessionId) throw new Error('session id required');
    const nonce = randomToken(16);
    return `${nonce}.${this.signer.sign(`${sessionId}|${nonce}`)}`;
  }

  verify(sessionId, token) {
    if (!sessionId || typeof token !== 'string' || token.length > 256) return false;
    const dot = token.indexOf('.');
    if (dot <= 0 || dot === token.length - 1) return false;
    return this.signer.verify(`${sessionId}|${token.slice(0, dot)}`, token.slice(dot + 1));
  }

  static requiresToken(method) {
    return !['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(String(method).toUpperCase());
  }
}
