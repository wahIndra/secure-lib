import type {
  ClaimMapping,
  CorsPolicy,
  CsrfTokenService,
  HttpRequestInspector,
  Principal,
  RateLimiter,
  RouteAccessPolicy,
  SecurityEvent,
} from './index.js';

type Req = any;
type Res = any;
type Next = (err?: unknown) => void;
type Middleware = (req: Req, res: Res, next: Next) => void;
type Logger = Partial<Record<'log' | 'info' | 'warn' | 'error', (msg: string) => void>>;
type EventListener = (event: SecurityEvent) => void;

/**
 * Security headers, CORS (preflights answered 204/403), rate limit (429), then inspection of path,
 * query, parsed body and selected headers. Same order as the Java SecurityFilterEngine.
 */
export declare function securityMiddleware(options?: {
  mode?: 'block' | 'monitor';
  /** Response headers to set; pass null to skip. */
  headers?: Record<string, string> | null;
  inspector?: HttpRequestInspector;
  cors?: CorsPolicy;
  rateLimiter?: RateLimiter;
  /** Default: req.ip. Configure Express `trust proxy` for your proxy only. */
  rateLimitKey?: (req: Req) => string;
  onEvent?: EventListener | EventListener[];
  logger?: Logger;
  failOpen?: boolean;
}): Middleware;

export declare function rateLimit(
  rateLimiter: RateLimiter,
  options?: { key?: (req: Req) => string; onEvent?: EventListener | EventListener[]; logger?: Logger },
): Middleware;

export declare function cors(policy: CorsPolicy): Middleware;

/** Sets req.user from the claims of an already verified token (default: req.auth.payload or req.auth). */
export declare function currentUser(mapping: ClaimMapping, options?: { getClaims?: (req: Req) => Record<string, unknown> | undefined }): Middleware;

export declare function errorHandler(options?: { logger?: Logger; onEvent?: EventListener | EventListener[] }): (err: unknown, req: Req, res: Res, next: Next) => void;

export declare function routePolicy(
  policy: RouteAccessPolicy,
  options?: { getPrincipal?: (req: Req) => Principal | null | undefined },
): Middleware;

export declare function csrfProtection(
  csrfService: CsrfTokenService,
  options?: { getSessionId?: (req: Req) => string | undefined; headerName?: string },
): Middleware;
