import { inputInspector, result } from './detectors.js';

export const DEFAULT_HEADERS = Object.freeze([
  'user-agent', 'referer', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'x-original-url', 'x-rewrite-url', 'origin',
]);

export const DEFAULT_MAX_VALUES = 2000;
export const DEFAULT_MAX_INSPECTED_CHARS = 256 * 1024;
export const DEFAULT_MAX_DEPTH = 20;

const safeName = (n) => String(n).replace(/[^A-Za-z0-9_.[\]-]/g, '_').slice(0, 64);

/**
 * Framework-neutral request inspection: the path, every query/body parameter name and value
 * (nested JSON included) and a set of headers. Reports never contain the offending values.
 *
 * Budget: inspection stops, and the request counts as malicious, once it exceeds `maxValues`
 * values, `maxInspectedChars` characters in total, or `maxDepth` levels of nesting. Skipping the
 * rest instead would let a payload hide behind padding. Same limits as the Java inspector.
 */
export class HttpRequestInspector {
  constructor({
    inspector = inputInspector,
    headers = DEFAULT_HEADERS,
    inspectBody = true,
    maxValues = DEFAULT_MAX_VALUES,
    maxInspectedChars = DEFAULT_MAX_INSPECTED_CHARS,
    maxDepth = DEFAULT_MAX_DEPTH,
  } = {}) {
    this.inspector = inspector;
    this.headers = new Set(headers.map((h) => h.toLowerCase()));
    this.inspectBody = inspectBody;
    Object.assign(this, { maxValues, maxInspectedChars, maxDepth });
  }

  /**
   * @param {{path?: string, query?: object, body?: unknown, headers?: object}} req
   */
  inspect({ path, query, body, headers } = {}) {
    const entries = [];
    const limits = [];
    let values = 0;
    let chars = 0;
    let stopped = false;
    const stop = (limit) => {
      stopped = true;
      limits.push(limit);
    };
    const check = (location, value) => {
      if (stopped) return false;
      if (value == null) return true;
      if (++values > this.maxValues) {
        stop('too-many-values');
        return false;
      }
      chars += value.length;
      if (chars > this.maxInspectedChars) {
        stop('inspection-budget-exceeded');
        return false;
      }
      const r = this.inspector.inspect(value);
      if (r.suspicious) entries.push({ location, result: r });
      return true;
    };
    const walk = (prefix, value, depth) => {
      if (stopped || value == null) return;
      if (depth > this.maxDepth) {
        stop('nesting-too-deep');
        return;
      }
      if (typeof value === 'string') check(prefix, value);
      else if (Array.isArray(value)) value.forEach((v) => walk(prefix, v, depth + 1));
      else if (typeof value === 'object') {
        for (const [k, v] of Object.entries(value)) {
          if (!check('param-name', k)) return;
          walk(`param:${safeName(k)}`, v, depth + 1);
        }
      }
    };

    // Request paths are always absolute; drop the leading slash so PATH_ABSOLUTE does not fire on every request.
    if (path) check('path', String(path).split('?')[0].replace(/^\/+/, ''));
    walk('query', query, 0);
    if (this.inspectBody) walk('body', body, 0);
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        if (this.headers.has(k.toLowerCase()) && !check(`header:${k}`, Array.isArray(v) ? v.join(', ') : v)) break;
      }
    }

    const findings = entries.flatMap((e) => e.result.findings);
    return {
      // Each location is scored on its own, so harmless MEDIUM hits in different fields do not add up.
      malicious: stopped || entries.some((e) => e.result.malicious),
      suspicious: stopped || entries.length > 0,
      budgetExceeded: stopped,
      findings: result(findings).findings,
      summary: [...limits, ...entries.map((e) => `${e.location}=[${e.result.findings.map((f) => `${f.ruleId}[${f.severity}]`).join(', ')}]`)]
        .join(', '),
    };
  }
}
