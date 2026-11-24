import { decode } from './normalize.js';
import { OwaspCategory, SecurityViolationError } from './owasp.js';

/** Map to HTTP 403, or 401 when `unauthenticated` is true. */
export class AccessDeniedError extends SecurityViolationError {
  constructor(message, unauthenticated = false) {
    super(OwaspCategory.BROKEN_ACCESS_CONTROL, message);
    this.name = 'AccessDeniedError';
    this.unauthenticated = unauthenticated;
  }
}

/**
 * A principal is any object `{ id, roles?, permissions?, tenantId? }`; roles and permissions
 * may be arrays or Sets.
 */
const has = (collection, value) => (collection instanceof Set ? collection.has(value) : Array.isArray(collection) && collection.includes(value));
const isAuthenticated = (p) => p != null && typeof p.id === 'string' && p.id !== '';

/**
 * Object-level checks to call after loading a record. Route rules alone do not stop IDOR:
 * `GET /orders/1042` passes "authenticated" for every logged-in user.
 */
export const AccessGuard = {
  requireAuthenticated(principal) {
    if (!isAuthenticated(principal)) throw new AccessDeniedError('authentication required', true);
    return principal;
  },

  hasAnyRole(principal, ...roles) {
    return principal != null && roles.some((r) => has(principal.roles, r));
  },

  requireAnyRole(principal, ...roles) {
    AccessGuard.requireAuthenticated(principal);
    if (!AccessGuard.hasAnyRole(principal, ...roles)) throw new AccessDeniedError('missing required role');
  },

  requireAllPermissions(principal, ...permissions) {
    AccessGuard.requireAuthenticated(principal);
    if (!permissions.every((p) => has(principal.permissions, p))) throw new AccessDeniedError('missing required permission');
  },

  isOwner(principal, resourceOwnerId) {
    return isAuthenticated(principal) && resourceOwnerId != null && String(principal.id) === String(resourceOwnerId);
  },

  /** IDOR protection: the resource must belong to the caller. A missing owner id is denied. */
  requireOwner(principal, resourceOwnerId) {
    AccessGuard.requireAuthenticated(principal);
    if (!AccessGuard.isOwner(principal, resourceOwnerId)) throw new AccessDeniedError('caller does not own resource');
  },

  requireOwnerOrRole(principal, resourceOwnerId, ...overrideRoles) {
    AccessGuard.requireAuthenticated(principal);
    if (!AccessGuard.isOwner(principal, resourceOwnerId) && !AccessGuard.hasAnyRole(principal, ...overrideRoles)) {
      throw new AccessDeniedError('caller does not own resource');
    }
  },

  /** Multi-tenant isolation. Both tenant ids must be present and equal. */
  requireSameTenant(principal, resourceTenantId) {
    AccessGuard.requireAuthenticated(principal);
    if (principal.tenantId == null || resourceTenantId == null || String(principal.tenantId) !== String(resourceTenantId)) {
      throw new AccessDeniedError('cross-tenant access');
    }
  },

  /**
   * Mass-assignment / privilege escalation guard. Pass the submitted object (e.g. req.body)
   * or a list of its keys. Nested objects are checked too, and __proto__/constructor keys are
   * always rejected (prototype pollution).
   */
  requireNoProtectedFields(submitted, ...protectedFields) {
    const blocked = new Set([...protectedFields, '__proto__', 'constructor', 'prototype'].map((f) => f.toLowerCase()));
    const visit = (value, depth) => {
      if (depth > 20 || value == null || typeof value !== 'object') return;
      for (const key of Array.isArray(value) ? [] : Object.keys(value)) {
        if (blocked.has(key.toLowerCase())) throw new AccessDeniedError('attempt to set protected field');
        visit(value[key], depth + 1);
      }
      if (Array.isArray(value)) value.forEach((v) => visit(v, depth + 1));
    };
    if (Array.isArray(submitted) && submitted.every((k) => typeof k === 'string')) {
      if (submitted.some((k) => blocked.has(k.toLowerCase()))) throw new AccessDeniedError('attempt to set protected field');
    } else {
      visit(submitted, 0);
    }
  },
};

/**
 * Returns the canonical form of a request path (query removed), or null if it contains
 * traversal, encoded separators, backslashes, null bytes or path parameters.
 */
export function canonicalizePath(rawPath) {
  if (!rawPath) return '/';
  let p = String(rawPath);
  p = p.split('?')[0].split('#')[0];
  if (/%2f|%5c|%00|%25/i.test(p)) return null;
  const decoded = decode(p);
  if (/[\\\0;]/.test(decoded)) return null;
  const out = [];
  for (const seg of decoded.split(/\/+/)) {
    if (!seg) continue;
    if (!isUnambiguousSegment(seg)) return null;
    out.push(seg);
  }
  return `/${out.join('/')}`;
}

/**
 * Rejects segments that some servers rewrite before routing, so the policy and the router cannot
 * disagree: dot-only segments, leading/trailing whitespace ("admin " or "%20admin"), trailing
 * dots ("admin." is "admin" on Windows/IIS), and control or invisible (format) characters.
 */
function isUnambiguousSegment(seg) {
  if (seg.replace(/\./g, '') === '' || seg.endsWith('.')) return false;
  if (/^[\s\p{Zs}]|[\s\p{Zs}]$/u.test(seg)) return false;
  return !/[\p{Cc}\p{Cf}]/u.test(seg);
}

const segments = (p) => p.split(/\/+/).filter(Boolean);

function segmentMatches(pattern, segment) {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === segment;
  const re = pattern.split('*').map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${re}$`, 's').test(segment);
}

/** Ant-style: '*' matches one segment (or part of one), '**' zero or more segments. */
function matches(pattern, pi, segs, si) {
  if (pi === pattern.length) return si === segs.length;
  if (pattern[pi] === '**') {
    for (let k = si; k <= segs.length; k++) if (matches(pattern, pi + 1, segs, k)) return true;
    return false;
  }
  return si < segs.length && segmentMatches(pattern[pi], segs[si]) && matches(pattern, pi + 1, segs, si + 1);
}

/**
 * Deny-by-default route authorization; first matching rule wins. Paths are canonicalized
 * first to close /admin/../, //admin, /admin;x, /%61dmin, /ADMIN and /admin/ bypasses.
 *
 * @example
 * const policy = new RouteAccessPolicy()
 *   .permitAll('GET', '/public/**')
 *   .hasAnyRole('*', '/admin/**', 'ADMIN')
 *   .authenticated('*', '/api/**');
 * policy.check(req.method, req.originalUrl, req.user);
 */
export class RouteAccessPolicy {
  /** Case-insensitive by default because many routers treat /ADMIN like /admin. */
  constructor({ ignoreCase = true } = {}) {
    this.ignoreCase = ignoreCase;
    this.rules = [];
  }

  #add(method, pattern, kind, roles = []) {
    const p = this.ignoreCase ? pattern.toLowerCase() : pattern;
    this.rules.push({ method: method.toUpperCase(), pattern: segments(p), kind, roles, source: `${method} ${pattern}` });
    return this;
  }

  permitAll(method, pattern) { return this.#add(method, pattern, 'PERMIT_ALL'); }
  authenticated(method, pattern) { return this.#add(method, pattern, 'AUTHENTICATED'); }
  denyAll(method, pattern) { return this.#add(method, pattern, 'DENY'); }
  hasAnyRole(method, pattern, ...roles) {
    if (!roles.length) throw new Error('at least one role is required');
    return this.#add(method, pattern, 'ROLES', roles);
  }

  /** @returns {{allowed: boolean, reason: string, matchedRule: string|null, unauthenticated: boolean}} */
  evaluate(method, rawPath, principal) {
    const deny = (reason, matchedRule = null, unauthenticated = false) => ({ allowed: false, reason, matchedRule, unauthenticated });
    const allow = (matchedRule) => ({ allowed: true, reason: 'allowed', matchedRule, unauthenticated: false });
    const canonical = canonicalizePath(rawPath);
    if (canonical == null) return deny('non-canonical path');
    const m = String(method ?? '').toUpperCase();
    const segs = segments(this.ignoreCase ? canonical.toLowerCase() : canonical);
    for (const r of this.rules) {
      if (r.method !== '*' && r.method !== m) continue;
      if (!matches(r.pattern, 0, segs, 0)) continue;
      const authed = isAuthenticated(principal);
      switch (r.kind) {
        case 'PERMIT_ALL': return allow(r.source);
        case 'DENY': return deny('route denied', r.source);
        case 'AUTHENTICATED': return authed ? allow(r.source) : deny('authentication required', r.source, true);
        default:
          if (!authed) return deny('authentication required', r.source, true);
          return AccessGuard.hasAnyRole(principal, ...r.roles) ? allow(r.source) : deny('missing required role', r.source);
      }
    }
    return deny('no matching rule (deny by default)');
  }

  check(method, rawPath, principal) {
    const d = this.evaluate(method, rawPath, principal);
    if (!d.allowed) throw new AccessDeniedError(d.reason, d.unauthenticated);
  }
}

// ---------------------------------------------------------------- identity from verified tokens

const DEFAULT_MAPPING = Object.freeze({
  idClaim: 'sub',
  roleClaims: Object.freeze(['roles', 'groups']),
  permissionClaims: Object.freeze(['scope', 'scp', 'permissions']),
  tenantClaim: null,
});

const mapping = (overrides) => Object.freeze({ ...DEFAULT_MAPPING, ...overrides });
const required = (value, name) => {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${name} is required`);
  return value;
};

/**
 * Where an identity provider puts the user id, roles, permissions and tenant. Use a preset or
 * `ClaimMappings.custom({...})`. Claim paths are dot-separated (`realm_access.roles`); a claim
 * whose name contains dots, such as Auth0's `https://example.com/roles`, is matched whole first.
 */
export const ClaimMappings = Object.freeze({
  /** Standard OIDC: `sub`; roles in `roles`/`groups`; `scope`/`scp`/`permissions`. */
  standard: () => DEFAULT_MAPPING,
  /** Keycloak realm roles, plus the roles of `clientId` when given. */
  keycloak: ({ clientId, tenantClaim = null } = {}) =>
    mapping({
      roleClaims: clientId ? ['realm_access.roles', `resource_access.${required(clientId, 'clientId')}.roles`] : ['realm_access.roles'],
      permissionClaims: ['scope'],
      tenantClaim,
    }),
  /** Auth0: roles in a namespaced custom claim (added by an Auth0 Action), RBAC permissions in `permissions`. */
  auth0: ({ rolesClaim, tenantClaim = null } = {}) =>
    mapping({ roleClaims: [required(rolesClaim, 'rolesClaim')], permissionClaims: ['permissions', 'scope'], tenantClaim }),
  /** Microsoft Entra ID: id `oid` (same for every app, unlike `sub`), app roles `roles`, scopes `scp`, tenant `tid`. */
  entraId: () => mapping({ idClaim: 'oid', roleClaims: ['roles'], permissionClaims: ['scp'], tenantClaim: 'tid' }),
  /** Okta: `groups` (add the groups claim to the authorization server), scopes `scp`. */
  okta: ({ tenantClaim = null } = {}) => mapping({ roleClaims: ['groups'], permissionClaims: ['scp'], tenantClaim }),
  /** AWS Cognito user pools: `cognito:groups`, scopes `scope`. */
  cognito: ({ tenantClaim = null } = {}) => mapping({ roleClaims: ['cognito:groups'], permissionClaims: ['scope'], tenantClaim }),
  /** Any other issuer. Unset fields keep the standard defaults. */
  custom: (fields = {}) => mapping(fields),
});

/** Looks up a claim by whole name first, then by dot path through nested objects. */
export function getClaim(claims, path) {
  if (claims == null || path == null) return undefined;
  if (Object.hasOwn(claims, path)) return claims[path];
  let current = claims;
  for (const part of path.split('.')) {
    if (current == null || typeof current !== 'object' || Array.isArray(current) || !Object.hasOwn(current, part)) return undefined;
    current = current[part];
  }
  return current;
}

function collect(value, out) {
  if (value == null) return;
  if (Array.isArray(value)) value.forEach((v) => collect(v, out));
  else if (typeof value === 'string') value.split(/[\s,]+/).filter(Boolean).forEach((s) => out.add(s));
}

/**
 * The caller, built from the claims of an ALREADY VERIFIED access token (for example the payload
 * returned by `jose`'s `jwtVerify`, or `req.auth` from express-oauth2-jwt-bearer), so identity comes
 * from the identity provider and never from the request. This function does not verify tokens.
 *
 * @returns {{ id: string, roles: Set<string>, permissions: Set<string>, tenantId: string|null, claims: object }}
 * @throws {AccessDeniedError} (unauthenticated) when the id claim is missing
 */
export function principalFromVerifiedClaims(claims, claimMapping = DEFAULT_MAPPING) {
  if (claims == null || typeof claims !== 'object') throw new AccessDeniedError('no verified token', true);
  const rawId = getClaim(claims, claimMapping.idClaim);
  const id = typeof rawId === 'string' || typeof rawId === 'number' ? String(rawId).trim() : '';
  if (!id) throw new AccessDeniedError(`token has no '${claimMapping.idClaim}' claim`, true);
  const roles = new Set();
  for (const p of claimMapping.roleClaims) collect(getClaim(claims, p), roles);
  const permissions = new Set();
  for (const p of claimMapping.permissionClaims) collect(getClaim(claims, p), permissions);
  const t = claimMapping.tenantClaim ? getClaim(claims, claimMapping.tenantClaim) : null;
  const tenantId = typeof t === 'string' || typeof t === 'number' ? String(t) : null;
  return Object.freeze({ id, roles, permissions, tenantId, claims: Object.freeze({ ...claims }) });
}
