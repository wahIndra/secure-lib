import { inputInspector, result } from './detectors.js';

export const DEFAULT_HEADERS = Object.freeze([
  'user-agent', 'referer', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'x-original-url', 'x-rewrite-url', 'origin',
]);

const MAX_PARAMETERS = 500;
const MAX_DEPTH = 10;

const safeName = (n) => String(n).replace(/[^A-Za-z0-9_.[\]-]/g, '_').slice(0, 64);

/**
 * Framework-neutral request inspection: the path, every query/body parameter name and value
 * (nested JSON included) and a set of headers. Reports never contain the offending values.
 */
export class HttpRequestInspector {
  constructor({ inspector = inputInspector, headers = DEFAULT_HEADERS, inspectBody = true } = {}) {
    this.inspector = inspector;
    this.headers = new Set(headers.map((h) => h.toLowerCase()));
    this.inspectBody = inspectBody;
  }

  /**
   * @param {{path?: string, query?: object, body?: unknown, headers?: object}} req
   */
  inspect({ path, query, body, headers } = {}) {
    const entries = [];
    let count = 0;
    let tooMany = false;
    let tooDeep = false;
    const add = (location, value) => {
      const r = this.inspector.inspect(value);
      if (r.suspicious) entries.push({ location, result: r });
    };
    const walk = (prefix, value, depth) => {
      if (value == null) return;
      // Fail closed: content below the depth limit is not inspected, so the request is rejected
      // rather than letting a payload hide in deep nesting.
      if (depth > MAX_DEPTH) {
        tooDeep = true;
        return;
      }
      if (++count > MAX_PARAMETERS) {
        tooMany = true;
        return;
      }
      if (typeof value === 'string') add(prefix, value);
      else if (typeof value === 'number' || typeof value === 'boolean') return;
      else if (Array.isArray(value)) value.forEach((v) => walk(prefix, v, depth + 1));
      else if (typeof value === 'object') {
        for (const [k, v] of Object.entries(value)) {
          add('param-name', k);
          walk(`param:${safeName(k)}`, v, depth + 1);
        }
      }
    };

    // Request paths are always absolute; drop the leading slash so PATH_ABSOLUTE does not fire on every request.
    if (path) add('path', String(path).split('?')[0].replace(/^\/+/, ''));
    walk('query', query, 0);
    if (this.inspectBody) walk('body', body, 0);
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        if (this.headers.has(k.toLowerCase())) add(`header:${k}`, Array.isArray(v) ? v.join(', ') : v);
      }
    }

    const findings = entries.flatMap((e) => e.result.findings);
    return {
      // Each location is scored on its own, so harmless MEDIUM hits in different fields do not add up.
      malicious: tooMany || tooDeep || entries.some((e) => e.result.malicious),
      suspicious: tooMany || tooDeep || entries.length > 0,
      findings: result(findings).findings,
      summary: [tooMany ? 'too-many-parameters' : null, tooDeep ? 'nesting-too-deep' : null, ...entries.map((e) => `${e.location}=[${e.result.findings.map((f) => `${f.ruleId}[${f.severity}]`).join(', ')}]`)]
        .filter(Boolean)
        .join(', '),
    };
  }
}
