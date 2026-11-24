export interface OwaspCategoryInfo {
  readonly id2025: string;
  readonly id2021: string | null;
  readonly title: string;
}

export declare const OwaspCategory: Readonly<{
  BROKEN_ACCESS_CONTROL: OwaspCategoryInfo;
  SECURITY_MISCONFIGURATION: OwaspCategoryInfo;
  SUPPLY_CHAIN_FAILURES: OwaspCategoryInfo;
  CRYPTOGRAPHIC_FAILURES: OwaspCategoryInfo;
  INJECTION: OwaspCategoryInfo;
  INSECURE_DESIGN: OwaspCategoryInfo;
  AUTHENTICATION_FAILURES: OwaspCategoryInfo;
  INTEGRITY_FAILURES: OwaspCategoryInfo;
  LOGGING_ALERTING_FAILURES: OwaspCategoryInfo;
  EXCEPTIONAL_CONDITIONS: OwaspCategoryInfo;
  SSRF: OwaspCategoryInfo;
}>;

export declare class SecurityViolationError extends Error {
  constructor(category: OwaspCategoryInfo, message: string);
  readonly category: OwaspCategoryInfo;
}

// ---------------------------------------------------------------- detection

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export declare const Severity: Readonly<{ LOW: 'LOW'; MEDIUM: 'MEDIUM'; HIGH: 'HIGH' }>;
export declare const MALICIOUS_SCORE: number;

export interface Finding {
  ruleId: string;
  category: OwaspCategoryInfo;
  severity: SeverityLevel;
  description: string;
}

export interface DetectionResult {
  findings: Finding[];
  score: number;
  malicious: boolean;
  suspicious: boolean;
}

export type RuleView = 'decoded' | 'stripped' | 'compact';

export interface Rule {
  id: string;
  category: OwaspCategoryInfo;
  severity: SeverityLevel;
  view: RuleView;
  pattern: RegExp;
  description: string;
}

export declare function decode(input: unknown): string;
export declare function normalize(input: unknown): string;

export declare class NormalizedInput {
  constructor(raw: unknown);
  readonly raw: string;
  readonly decoded: string;
  readonly stripped: string;
  readonly compact: string;
  view(name: RuleView): string;
}

export declare class RuleBasedDetector {
  constructor(rules: Rule[]);
  readonly rules: readonly Rule[];
  inspect(input: string | NormalizedInput | null | undefined): DetectionResult;
  isMalicious(input: string | null | undefined): boolean;
  assertSafe(input: string | null | undefined): void;
}

export declare class InputInspector {
  constructor(detectors?: RuleBasedDetector[]);
  inspect(input: string | null | undefined): DetectionResult;
  isMalicious(input: string | null | undefined): boolean;
}

export declare const inputInspector: InputInspector;
export declare const sqlInjectionDetector: RuleBasedDetector;
export declare const xssDetector: RuleBasedDetector;
export declare const commandInjectionDetector: RuleBasedDetector;
export declare const pathTraversalDetector: RuleBasedDetector;
export declare const sqlInjectionRules: Rule[];
export declare const xssRules: Rule[];
export declare const commandInjectionRules: Rule[];
export declare const pathTraversalRules: Rule[];

// ---------------------------------------------------------------- path traversal

export declare class PathTraversalError extends SecurityViolationError {}

export declare class PathTraversalGuard {
  static forBaseDirectory(baseDirectory: string): PathTraversalGuard;
  readonly base: string;
  resolve(userPath: string): string;
  isSafe(userPath: string): boolean;
}

export declare const SafeFileName: {
  isSafe(name: unknown): boolean;
  require(name: string): string;
  sanitize(name: unknown): string;
  extension(name: string): string;
};

// ---------------------------------------------------------------- access control

export interface Principal {
  id: string;
  roles?: string[] | Set<string>;
  permissions?: string[] | Set<string>;
  tenantId?: string | null;
}

export declare class AccessDeniedError extends SecurityViolationError {
  constructor(message: string, unauthenticated?: boolean);
  readonly unauthenticated: boolean;
}

export declare const AccessGuard: {
  requireAuthenticated<P extends Principal>(principal: P | null | undefined): P;
  hasAnyRole(principal: Principal | null | undefined, ...roles: string[]): boolean;
  requireAnyRole(principal: Principal | null | undefined, ...roles: string[]): void;
  requireAllPermissions(principal: Principal | null | undefined, ...permissions: string[]): void;
  isOwner(principal: Principal | null | undefined, resourceOwnerId: unknown): boolean;
  requireOwner(principal: Principal | null | undefined, resourceOwnerId: unknown): void;
  requireOwnerOrRole(principal: Principal | null | undefined, resourceOwnerId: unknown, ...overrideRoles: string[]): void;
  requireSameTenant(principal: Principal | null | undefined, resourceTenantId: unknown): void;
  requireNoProtectedFields(submitted: object | string[], ...protectedFields: string[]): void;
};

export interface AccessDecision {
  allowed: boolean;
  reason: string;
  matchedRule: string | null;
  unauthenticated: boolean;
}

export declare function canonicalizePath(rawPath: string | null | undefined): string | null;

export declare class RouteAccessPolicy {
  constructor(options?: { ignoreCase?: boolean });
  permitAll(method: string, pattern: string): this;
  authenticated(method: string, pattern: string): this;
  hasAnyRole(method: string, pattern: string, ...roles: string[]): this;
  denyAll(method: string, pattern: string): this;
  evaluate(method: string, rawPath: string, principal: Principal | null | undefined): AccessDecision;
  check(method: string, rawPath: string, principal: Principal | null | undefined): void;
}

// ---------------------------------------------------------------- identity from verified tokens

export interface ClaimMapping {
  readonly idClaim: string;
  readonly roleClaims: readonly string[];
  readonly permissionClaims: readonly string[];
  readonly tenantClaim: string | null;
}

export declare const ClaimMappings: Readonly<{
  standard(): ClaimMapping;
  keycloak(options?: { clientId?: string; tenantClaim?: string | null }): ClaimMapping;
  auth0(options: { rolesClaim: string; tenantClaim?: string | null }): ClaimMapping;
  entraId(): ClaimMapping;
  okta(options?: { tenantClaim?: string | null }): ClaimMapping;
  cognito(options?: { tenantClaim?: string | null }): ClaimMapping;
  custom(fields?: Partial<ClaimMapping>): ClaimMapping;
}>;

export interface VerifiedPrincipal extends Principal {
  readonly id: string;
  readonly roles: Set<string>;
  readonly permissions: Set<string>;
  readonly tenantId: string | null;
  readonly claims: Readonly<Record<string, unknown>>;
}

/** Build the caller from the claims of an ALREADY VERIFIED token. Does not verify tokens. */
export declare function principalFromVerifiedClaims(claims: Record<string, unknown>, mapping?: ClaimMapping): VerifiedPrincipal;
export declare function getClaim(claims: Record<string, unknown> | null | undefined, path: string): unknown;

// ---------------------------------------------------------------- SSRF

export declare class SsrfError extends SecurityViolationError {}
export declare function isBlockedAddress(ip: string): boolean;

export interface UrlGuardOptions {
  schemes?: string[];
  /** Exact hosts or "*.example.com" suffixes. Empty means any public host. */
  allowHosts?: string[];
  ports?: number[];
  allowPrivateNetworks?: boolean;
  resolver?: (host: string) => Promise<string[]>;
}

export interface ValidatedUrl {
  url: URL;
  host: string;
  port: number;
  /** Connect to one of these, not to a fresh DNS lookup of the host. */
  addresses: string[];
}

export declare class UrlGuard {
  constructor(options?: UrlGuardOptions);
  validate(rawUrl: string): Promise<ValidatedUrl>;
  isAllowed(rawUrl: string): Promise<boolean>;
}

// ---------------------------------------------------------------- crypto / auth

export declare const DEFAULT_ITERATIONS: number;

export declare class PasswordHasher {
  constructor(iterations?: number);
  readonly iterations: number;
  hash(password: string): Promise<string>;
  verify(password: string, stored: string): Promise<boolean>;
  needsRehash(stored: string): boolean;
}

export declare class HmacSigner {
  constructor(secretKey: string | Uint8Array);
  sign(data: string | Uint8Array): string;
  verify(data: string | Uint8Array, signature: string): boolean;
  verifyHex(payload: string | Uint8Array, hexSignature: string): boolean;
}

export declare class LoginAttemptLimiter {
  constructor(options?: { maxFailures?: number; windowMs?: number; lockoutMs?: number; maxTrackedKeys?: number; now?: () => number });
  isLocked(key: string): boolean;
  retryAfterMs(key: string): number;
  recordFailure(key: string): void;
  recordSuccess(key: string): void;
  readonly trackedKeys: number;
  /** Entries evicted to stay under the cap since start. A steady rise means a flood: alert on it. */
  readonly evictionCount: number;
  /** Reports a LOGIN_LOCKED event whenever a key becomes locked. */
  onLockout(listener: (event: SecurityEvent) => void): this;
}

export declare function randomToken(bytes?: number): string;
export declare function constantTimeEquals(a: string, b: string): boolean;
export declare function sha256Token(token: string): string;
export declare function validatePassword(
  password: string,
  options?: { username?: string; minLength?: number; maxLength?: number },
): string[];

// ---------------------------------------------------------------- web

export declare const DEFAULT_CSP: string;
export declare const LEAKY_HEADERS: readonly string[];
export declare function securityHeaders(
  overrides?: Record<string, string | null>,
  options?: { noStore?: boolean },
): Record<string, string>;

export declare class CsrfTokenService {
  constructor(secretKey: string | Uint8Array);
  generate(sessionId: string): string;
  verify(sessionId: string | null | undefined, token: unknown): boolean;
  static requiresToken(method: string): boolean;
}

export declare function forHtml(s: unknown): string;
export declare function forHtmlAttribute(s: unknown): string;
export declare function forJavaScript(s: unknown): string;
export declare function forUrlComponent(s: unknown): string;
export declare function forCssString(s: unknown): string;
export declare function safeUrl(url: unknown): string;

export declare const SafeSql: {
  allowlisted(value: unknown, allowed: string[]): string;
  mapped(value: unknown, publicToColumn: Record<string, string>): string;
  quoteIdentifier(name: string): string;
  direction(value: unknown, defaultDirection?: 'ASC' | 'DESC'): 'ASC' | 'DESC';
  placeholders(count: number, options?: { style?: '?' | 'pg'; start?: number }): string;
  escapeLike(value: string): string;
  clamp(value: unknown, min: number, max: number, defaultValue: number): number;
};

export declare function safeCommand(
  executable: string,
  userArgs?: string[],
  constantOptions?: string[],
): [string, string[]];

export declare const PUBLIC_ERROR_MESSAGE: string;
export declare function sanitizeForLog(value: unknown, maxLength?: number): string;
export declare function maskSecrets(value: string): string;
export declare function logError(logger: { error?: (msg: string) => void; log?: (msg: string) => void }, error: unknown, context?: string): string;
export declare function publicErrorBody(incidentId: string): { error: string; incidentId: string };

export declare const DEFAULT_HEADERS: readonly string[];

export interface InspectionReport {
  malicious: boolean;
  suspicious: boolean;
  /** A limit was hit, so part of the request was not inspected; counted as malicious. */
  budgetExceeded: boolean;
  findings: Finding[];
  /** e.g. "param:id=[SQLI_PG_SLEEP[HIGH]]". Never contains the offending values. */
  summary: string;
}

export declare class HttpRequestInspector {
  constructor(options?: { inspector?: InputInspector; headers?: string[]; inspectBody?: boolean;
    maxValues?: number; maxInspectedChars?: number; maxDepth?: number });
  inspect(req?: { path?: string; query?: unknown; body?: unknown; headers?: Record<string, string | string[] | undefined> }): InspectionReport;
}

// ---------------------------------------------------------------- API protection

export declare const DEFAULT_MAX_VALUES: number;
export declare const DEFAULT_MAX_INSPECTED_CHARS: number;
export declare const DEFAULT_MAX_DEPTH: number;

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterMs: number;
  resetMs: number;
  /** RateLimit-Limit / -Remaining / -Reset, plus Retry-After when limited */
  headers: Record<string, string>;
}

export declare class RateLimiter {
  constructor(options: { capacity: number; periodMs: number; maxKeys?: number; now?: () => number });
  static perSecond(requests: number): RateLimiter;
  static perMinute(requests: number): RateLimiter;
  tryAcquire(key: string | null | undefined): RateLimitDecision;
  readonly trackedKeys: number;
}

export declare function isSafeRedirect(requested: unknown, allowedHosts?: string[]): boolean;
export declare function safeRedirect(requested: unknown, fallback?: string, allowedHosts?: string[]): string;

export declare class CorsPolicy {
  constructor(options: {
    allowOrigins: string[];
    allowMethods?: string[];
    allowHeaders?: string[];
    exposeHeaders?: string[];
    allowCredentials?: boolean;
    maxAgeSeconds?: number;
  });
  isAllowedOrigin(origin: unknown): boolean;
  evaluate(request: { origin?: string; method?: string; requestMethod?: string; requestHeaders?: string }): {
    preflight: boolean;
    allowed: boolean;
    headers: Record<string, string>;
  };
}

export type SecurityEventTypeName =
  | 'REQUEST_BLOCKED' | 'REQUEST_FLAGGED' | 'RATE_LIMITED' | 'CORS_REJECTED' | 'ACCESS_DENIED' | 'LOGIN_LOCKED' | 'INSPECTION_ERROR';

export declare const SecurityEventType: Readonly<Record<SecurityEventTypeName, SecurityEventTypeName>>;

export interface SecurityEvent {
  readonly type: SecurityEventTypeName;
  readonly incidentId: string;
  readonly timestamp: string;
  readonly method?: string;
  readonly path?: string;
  readonly remoteAddress?: string;
  readonly principalId?: string;
  readonly owasp?: string;
  readonly category?: string;
  readonly ruleIds: readonly string[];
  readonly detail?: string;
}

export declare function securityEvent(
  type: SecurityEventTypeName,
  fields?: { incidentId?: string; method?: string; path?: string; remoteAddress?: string; principalId?: string;
    category?: OwaspCategoryInfo; ruleIds?: string[]; detail?: string },
): SecurityEvent;

export declare function emitSecurityEvent(
  event: SecurityEvent,
  listeners?: Array<(event: SecurityEvent) => void>,
  logger?: { log?: (m: string) => void; info?: (m: string) => void; warn?: (m: string) => void },
): void;
