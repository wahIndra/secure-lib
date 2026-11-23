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
  constructor(secretKey: string | Buffer | Uint8Array);
  sign(data: string | Buffer): string;
  verify(data: string | Buffer, signature: string): boolean;
  verifyHex(payload: string | Buffer, hexSignature: string): boolean;
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
  constructor(secretKey: string | Buffer | Uint8Array);
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
  findings: Finding[];
  /** e.g. "param:id=[SQLI_PG_SLEEP[HIGH]]". Never contains the offending values. */
  summary: string;
}

export declare class HttpRequestInspector {
  constructor(options?: { inspector?: InputInspector; headers?: string[]; inspectBody?: boolean });
  inspect(req?: { path?: string; query?: unknown; body?: unknown; headers?: Record<string, string | string[] | undefined> }): InspectionReport;
}
