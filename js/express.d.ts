import type { CsrfTokenService, HttpRequestInspector, Principal, RouteAccessPolicy } from './index.js';

type Req = any;
type Res = any;
type Next = (err?: unknown) => void;
type Middleware = (req: Req, res: Res, next: Next) => void;
type Logger = Partial<Record<'log' | 'info' | 'warn' | 'error', (msg: string) => void>>;

export declare function securityMiddleware(options?: {
  mode?: 'block' | 'monitor';
  /** Response headers to set; pass null to skip. */
  headers?: Record<string, string> | null;
  inspector?: HttpRequestInspector;
  logger?: Logger;
  failOpen?: boolean;
}): Middleware;

export declare function errorHandler(options?: { logger?: Logger }): (err: unknown, req: Req, res: Res, next: Next) => void;

export declare function routePolicy(
  policy: RouteAccessPolicy,
  options?: { getPrincipal?: (req: Req) => Principal | null | undefined },
): Middleware;

export declare function csrfProtection(
  csrfService: CsrfTokenService,
  options?: { getSessionId?: (req: Req) => string | undefined; headerName?: string },
): Middleware;
