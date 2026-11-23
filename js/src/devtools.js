/**
 * Developer tools: source scanner, payload explainer and local attack probe. Same rules and
 * payload files as the Java implementation (io.github.wahindra.secure.devtools).
 */
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { NormalizedInput } from './normalize.js';
import { inputInspector, MALICIOUS_SCORE } from './detectors.js';
import { OwaspCategory } from './owasp.js';
import { isBlockedAddress } from './ssrf.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Packaged copy (js/devtools, created by `npm pack`) first, then the repository's shared folder. */
function dataFile(name) {
  for (const dir of [path.join(here, '..', 'devtools'), path.join(here, '..', '..', 'devtools')]) {
    const p = path.join(dir, name);
    if (fs.existsSync(p)) return p;
  }
  throw new Error(`${name} not found`);
}

const SEVERITY_ORDER = { LOW: 1, MEDIUM: 2, HIGH: 3 };

// ---------------------------------------------------------------- rules

/** Parses the rule file format documented at the top of scan-rules.txt. */
export function parseRules(text) {
  const rules = [];
  const ids = new Set();
  let block = {};
  const flush = (lineNo) => {
    if (!Object.keys(block).length) return;
    for (const k of ['id', 'lang', 'severity', 'owasp', 'pattern', 'message', 'fix']) {
      if (!block[k]) throw new Error(`missing '${k}' in rule ${block.id ?? '?'} (line ${lineNo})`);
    }
    if (ids.has(block.id)) throw new Error(`duplicate rule id ${block.id}`);
    ids.add(block.id);
    const owasp = OwaspCategory[block.owasp];
    if (!owasp) throw new Error(`unknown owasp category ${block.owasp}`);
    rules.push({
      id: block.id,
      langs: new Set(block.lang.split(/\s*,\s*/).map((s) => s.trim().toLowerCase())),
      severity: block.severity.toUpperCase(),
      owasp,
      maskStrings: block.scope !== 'raw',
      pattern: new RegExp(block.pattern, (block.flags ?? '').includes('i') ? 'i' : ''),
      unless: block.unless ? new RegExp(block.unless, 'i') : null,
      unlessFile: block['unless-file'] ? new RegExp(block['unless-file']) : null,
      message: block.message,
      fix: block.fix,
    });
    block = {};
  };
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    if (line.trim() === '') return flush(i + 1);
    if (line.startsWith('#')) return undefined;
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error(`line ${i + 1}: expected 'key: value'`);
    block[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
    return undefined;
  });
  flush(lines.length);
  return rules;
}

let cachedRules;
export function defaultRules() {
  cachedRules ??= parseRules(fs.readFileSync(dataFile('scan-rules.txt'), 'utf8'));
  return cachedRules;
}

// ---------------------------------------------------------------- scanner

export const DEFAULT_EXCLUDED_DIRS = new Set([
  '.git', '.svn', '.hg', '.idea', '.vscode', '.gradle', '.mvn', 'node_modules', 'target', 'build', 'dist',
  'out', 'coverage', 'vendor', 'bower_components', '.next', '.nuxt', 'test-vectors',
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const IGNORE = /secure-scan:ignore(?:\s+([A-Z0-9_,\s]+?))?(?:\s+--|\s*$|\s*\*\/|\s*-->)/;

/** Language family for a file name, or null if the scanner does not handle it. */
export function langOf(fileName) {
  const n = fileName.toLowerCase();
  if (/\.(?:min\.js|d\.ts|map)$/.test(n)) return null;
  if (/\.(?:java|kt|kts|groovy|scala)$/.test(n)) return 'java';
  if (/\.(?:js|mjs|cjs|ts|mts|cts|jsx|tsx)$/.test(n)) return 'js';
  if (/\.(?:html?|jspx?|vue|svelte|ftl|hbs|handlebars|ejs|njk|twig|thymeleaf)$/.test(n)) return 'template';
  const base = n.slice(Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\')) + 1);
  if (/\.(?:properties|ya?ml|conf)$/.test(n) || base === '.env' || base.startsWith('.env.')) return 'config';
  return null;
}

function isCommentLine(t, lang) {
  if (lang === 'config') return /^[#!;]/.test(t);
  if (lang === 'template') return t.startsWith('<!--') || t.startsWith('<%--') || t.startsWith('{{!--');
  return t.startsWith('//') || t.startsWith('/*') || t.startsWith('*');
}

/** Replaces string-literal contents with 'x' (quotes and ${...} kept) so code rules ignore text. */
export function maskStrings(line, lang) {
  if (lang === 'config' || lang === 'template') return line;
  let out = '';
  let quote = '';
  let interpolation = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (interpolation > 0) {
      if (c === '{') interpolation++;
      else if (c === '}') interpolation--;
      out += c;
    } else if (quote === '`' && c === '$' && line[i + 1] === '{') {
      interpolation = 1;
      out += '${';
      i++;
    } else if (!quote) {
      if (c === '"' || c === "'" || (c === '`' && lang === 'js')) quote = c;
      else if (c === '/' && line[i + 1] === '/') return out + line.slice(i);
      out += c;
    } else if (c === '\\' && i + 1 < line.length) {
      out += 'xx';
      i++;
    } else if (c === quote) {
      quote = '';
      out += c;
    } else {
      out += 'x';
    }
  }
  return out;
}

/** null = nothing suppressed, empty set = everything, otherwise the listed ids. */
function ignoredRules(line, previous, lang) {
  const above = previous != null && isCommentLine(previous.trim(), lang) ? previous : null;
  let result = null;
  for (const l of [line, above]) {
    if (!l || !l.includes('secure-scan:ignore')) continue;
    const m = l.match(IGNORE);
    if (!m) continue;
    if (!m[1] || !m[1].trim()) return new Set();
    result ??= new Set();
    for (const id of m[1].split(/[,\s]+/)) if (id) result.add(id);
  }
  return result;
}

export class SourceScanner {
  constructor({ rules = defaultRules(), excludedDirs = DEFAULT_EXCLUDED_DIRS } = {}) {
    this.rules = rules;
    this.excludedDirs = new Set(excludedDirs);
  }

  /** Scans text as if it came from a file with the given name. */
  scanText(fileName, content) {
    const lang = langOf(fileName);
    return lang ? this.#scanContent(fileName, lang, content) : [];
  }

  /** @returns {{findings: object[], filesScanned: number, ruleCount: number}} */
  scan(...paths) {
    const findings = [];
    let filesScanned = 0;
    const visit = (p, isRoot) => {
      let st;
      try {
        st = fs.statSync(p);
      } catch {
        return;
      }
      if (st.isDirectory()) {
        if (!isRoot && this.excludedDirs.has(path.basename(p))) return;
        for (const e of fs.readdirSync(p)) visit(path.join(p, e), false);
      } else if (st.isFile() && st.size <= MAX_FILE_BYTES) {
        const lang = langOf(path.basename(p));
        if (!lang) return;
        filesScanned++;
        findings.push(...this.#scanContent(p, lang, fs.readFileSync(p, 'utf8')));
      }
    };
    for (const p of paths.length ? paths : ['.']) visit(p, true);
    findings.sort((a, b) => SEVERITY_ORDER[b.rule.severity] - SEVERITY_ORDER[a.rule.severity]
      || a.file.localeCompare(b.file) || a.line - b.line);
    return { findings, filesScanned, ruleCount: this.rules.length };
  }

  #scanContent(file, lang, content) {
    const applicable = this.rules.filter((r) => r.langs.has(lang) && !(r.unlessFile && r.unlessFile.test(content)));
    if (!applicable.length) return [];
    const out = [];
    const lines = content.split(/\r?\n/);
    let inBlockComment = false;
    lines.forEach((raw, i) => {
      const trimmed = raw.trim();
      // Whole-line comments are skipped so documentation examples do not raise findings.
      if (inBlockComment) {
        if (trimmed.includes('*/')) inBlockComment = false;
        return;
      }
      if (isCommentLine(trimmed, lang)) {
        if (trimmed.startsWith('/*') && !trimmed.includes('*/')) inBlockComment = true;
        return;
      }
      const masked = maskStrings(raw, lang);
      // Only Java/JS have // comments; in config and templates "//" is usually part of a URL.
      const commentAt = lang === 'java' || lang === 'js' ? masked.indexOf('//') : -1;
      const code = commentAt >= 0 ? raw.slice(0, commentAt) : raw;
      const maskedCode = commentAt >= 0 ? masked.slice(0, commentAt) : masked;
      const ignored = ignoredRules(raw, i > 0 ? lines[i - 1] : null, lang);
      for (const rule of applicable) {
        if (ignored && (ignored.size === 0 || ignored.has(rule.id))) continue;
        const m = rule.pattern.exec(rule.maskStrings ? maskedCode : code);
        if (m && !(rule.unless && rule.unless.test(code))) {
          out.push({ rule, file, line: i + 1, column: m.index + 1, source: trimmed.length > 200 ? `${trimmed.slice(0, 200)}...` : trimmed });
        }
      }
    });
    return out;
  }
}

export function atLeast(findings, minimum) {
  return findings.filter((f) => SEVERITY_ORDER[f.rule.severity] >= SEVERITY_ORDER[minimum]);
}

const rel = (file, base) => {
  if (!base) return file;
  const r = path.relative(base, file);
  return r && !r.startsWith('..') && !path.isAbsolute(r) ? r : file;
};

/** `path:line:col: SEVERITY RULE message`, which IDE terminals and VS Code problem matchers pick up. */
export function toText(report, { base = process.cwd(), withFix = true } = {}) {
  let s = '';
  for (const f of report.findings) {
    const r = f.rule;
    s += `${rel(f.file, base)}:${f.line}:${f.column}: ${r.severity} ${r.id} [${r.owasp.id2025} ${r.owasp.title}] ${r.message}\n    ${f.source}\n`;
    if (withFix) s += `    fix: ${r.fix}\n`;
  }
  const c = (sev) => report.findings.filter((f) => f.rule.severity === sev).length;
  s += `${report.findings.length ? `${report.findings.length} finding(s)` : 'No findings'} (${c('HIGH')} HIGH, ${c('MEDIUM')} MEDIUM, ${c('LOW')} LOW) in ${report.filesScanned} file(s), ${report.ruleCount} rules.\n`;
  return s;
}

export function toJson(report, { base = process.cwd() } = {}) {
  return JSON.stringify({
    filesScanned: report.filesScanned,
    findings: report.findings.map((f) => ({
      rule: f.rule.id, severity: f.rule.severity, owasp: f.rule.owasp.id2025, category: f.rule.owasp.title,
      file: rel(f.file, base), line: f.line, column: f.column, message: f.rule.message, fix: f.rule.fix, source: f.source,
    })),
  });
}

const level = (s) => (s === 'HIGH' ? 'error' : s === 'MEDIUM' ? 'warning' : 'note');

/** SARIF 2.1.0 for the VS Code SARIF Viewer, IntelliJ and GitHub code scanning. */
export function toSarif(report, { base = process.cwd() } = {}) {
  const used = new Map(report.findings.map((f) => [f.rule.id, f.rule]));
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'secure-scan',
          informationUri: 'https://github.com/wahIndra/secure-lib',
          rules: [...used.values()].map((r) => ({
            id: r.id,
            shortDescription: { text: r.message },
            help: { text: r.fix },
            properties: { tags: ['security', r.owasp.id2025] },
            defaultConfiguration: { level: level(r.severity) },
          })),
        },
      },
      results: report.findings.map((f) => ({
        ruleId: f.rule.id,
        level: level(f.rule.severity),
        message: { text: `${f.rule.message}. Fix: ${f.rule.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: rel(f.file, base).replace(/\\/g, '/') }, region: { startLine: f.line, startColumn: f.column } } }],
      })),
    }],
  });
}

// ---------------------------------------------------------------- check

/** How the request filter sees one value. */
export function explain(value) {
  const n = new NormalizedInput(value);
  const r = inputInspector.inspect(value);
  return {
    input: value,
    decoded: n.decoded,
    stripped: n.stripped,
    verdict: r.malicious ? 'MALICIOUS (would be blocked)' : r.suspicious ? 'suspicious (logged in monitor mode, not blocked)' : 'clean',
    score: r.score,
    threshold: MALICIOUS_SCORE,
    malicious: r.malicious,
    findings: r.findings,
  };
}

// ---------------------------------------------------------------- probe

export const DB_ERROR = new RegExp(
  'syntax error at or near|unterminated quoted string|PSQLException|org\\.postgresql|SQLSyntaxErrorException'
  + '|SQLException|You have an error in your SQL syntax|mysql_fetch|ORA-\\d{5}|SQLITE_ERROR|sqlite3\\.'
  + '|Unclosed quotation mark|Incorrect syntax near|org\\.hibernate|JDBCException|QueryFailedError'
  // "ERROR: secprobe" is how PostgreSQL reports the RAISE EXCEPTION payload; the bare word is not
  // enough because a safe page may echo the (encoded) payload back.
  + '|SequelizeDatabaseError|invalid input syntax for|ERROR:\\s+invalid input|ERROR:\\s+secprobe',
  'i',
);
const PASSWD = /root:[x*!]?:0:0:|\[fonts\]|for 16-bit app support/;
const ID_OUTPUT = /uid=\d+\([^)]*\)\s+gid=\d+/;
const STACK_TRACE = /\bat [\w$.]+\([\w$]+\.java:\d+\)|Exception in thread|java\.lang\.\w+Exception|\n\s+at .+\(.+\.(?:js|ts):\d+:\d+\)|Traceback \(most recent call last\)/;
const DELAY_THRESHOLD_MS = 2500;

export function probePayloads() {
  return fs.readFileSync(dataFile('probe-payloads.txt'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l && !l.startsWith('#') && l.includes('\t'))
    .map((l) => [l.slice(0, l.indexOf('\t')), l.slice(l.indexOf('\t') + 1)]);
}

const encode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** Refuses targets outside loopback/private networks unless allowRemote is set. */
export async function checkTargetAllowed({ url, body, headers = {}, allowRemote = false }) {
  if (!url.includes('FUZZ') && !(body ?? '').includes('FUZZ') && !Object.values(headers).some((v) => String(v).includes('FUZZ'))) {
    throw new Error('put FUZZ where the payload should go (URL, --data or --header)');
  }
  const u = new URL(url.replaceAll('FUZZ', '1'));
  if (!/^https?:$/.test(u.protocol)) throw new Error('target must be an http(s) URL');
  if (allowRemote) return;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map((a) => a.address);
  for (const a of addrs) {
    if (!isBlockedAddress(a)) {
      throw new Error(`${host} resolves to public address ${a}. The probe only targets local/private servers by default;`
        + ' pass --allow-remote only for systems you own or are authorized to test.');
    }
  }
}

async function send(t, payload) {
  const start = performance.now();
  const r = { status: 0, body: '', millis: 0, error: null };
  try {
    const headers = { 'user-agent': 'secure-probe/0.1' };
    for (const [k, v] of Object.entries(t.headers ?? {})) headers[k] = String(v).replaceAll('FUZZ', payload);
    let body;
    if (t.body != null) {
      const json = /^\s*[{[]/.test(t.body);
      body = t.body.replaceAll('FUZZ', json ? JSON.stringify(payload).slice(1, -1) : encode(payload));
      if (!Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) {
        headers['content-type'] = json ? 'application/json' : 'application/x-www-form-urlencoded';
      }
    }
    const res = await fetch(t.url.replaceAll('FUZZ', encode(payload)), {
      method: t.method ?? (t.body != null ? 'POST' : 'GET'),
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(t.timeoutMs ?? 15000),
    });
    r.status = res.status;
    r.body = (await res.text()).slice(0, 2 * 1024 * 1024);
  } catch (e) {
    r.error = `${e.name}: ${e.message}`;
  }
  r.millis = Math.round(performance.now() - start);
  return r;
}

const differs = (a, b) => a.status !== b.status
  || Math.abs(a.body.length - b.body.length) > Math.max(50, Math.max(a.body.length, b.body.length) / 10);

/**
 * Sends each payload with FUZZ replaced and reports responses that show the attack worked.
 * Only point it at systems you own or are authorized to test.
 *
 * @param {{url: string, method?: string, body?: string, headers?: object, baseline?: string,
 *          only?: string[], allowRemote?: boolean, timeoutMs?: number}} target
 */
export async function probe(target, onResult = () => {}) {
  await checkTargetAllowed(target);
  const baseline = target.baseline ?? '1';
  const b1 = await send(target, baseline);
  const b2 = await send(target, baseline);
  if (b1.error) throw new Error(`baseline request failed: ${b1.error}`);
  const baseMillis = Math.max(b1.millis, b2.millis);
  const baseHasMarker = b1.body.includes('94011');
  const baseHasDbError = DB_ERROR.test(b1.body);
  const only = new Set(target.only ?? []);
  const results = [];
  let pendingTrue = null;
  for (const [check, payload] of probePayloads()) {
    const family = check.startsWith('sqli') ? 'sqli' : check.startsWith('cmd') ? 'cmd' : check;
    if (only.size && !only.has(family) && !only.has(check)) continue;
    const r = await send(target, payload);
    let severity = null;
    let verdict;
    if (r.error) verdict = `request failed: ${r.error}`;
    else if (r.body.includes('request_rejected')) verdict = `blocked by secure filter (HTTP ${r.status})`;
    else {
      verdict = 'no sign of vulnerability';
      const delayed = r.millis - baseMillis >= DELAY_THRESHOLD_MS;
      if (check === 'sqli-error' && !baseHasDbError && DB_ERROR.test(r.body.replaceAll(payload, ''))) {
        severity = 'HIGH';
        verdict = 'database error in response: SQL injection likely';
      } else if ((check === 'sqli-time' || check === 'cmd-time') && delayed) {
        severity = 'HIGH';
        verdict = `response delayed ${r.millis - baseMillis} ms: ${check === 'cmd-time' ? 'command' : 'time-based SQL'} injection likely`;
      } else if (check === 'xss' && r.body.includes(payload)) {
        severity = 'HIGH';
        verdict = 'payload reflected unencoded: XSS';
      } else if (check === 'path' && PASSWD.test(r.body)) {
        severity = 'HIGH';
        verdict = 'system file content returned: path traversal';
      } else if (check === 'cmd' && ID_OUTPUT.test(r.body)) {
        severity = 'HIGH';
        verdict = 'command output in response: command injection';
      } else if (check === 'ssti' && !baseHasMarker && r.body.includes('94011')) {
        severity = 'HIGH';
        verdict = 'expression evaluated (31337*3=94011): template injection';
      } else if (check === 'sqli-true') {
        pendingTrue = { r, payload };
      } else if (check === 'sqli-false' && pendingTrue) {
        if (differs(pendingTrue.r, r) && differs(r, b1) && !differs(pendingTrue.r, b1)) {
          severity = 'MEDIUM';
          verdict = `response changes with the injected condition (${pendingTrue.payload} vs this): boolean-based SQL injection possible`;
        }
        pendingTrue = null;
      }
      if (!severity && r.status >= 500 && STACK_TRACE.test(r.body)) {
        severity = 'MEDIUM';
        verdict = `HTTP ${r.status} with stack trace in body: unhandled error leaks details (A10)`;
      } else if (!severity && r.status >= 500) {
        severity = 'LOW';
        verdict = `HTTP ${r.status}: input causes a server error; check the logs`;
      }
    }
    const res = { check, payload, status: r.status, millis: r.millis, severity, verdict, vulnerable: severity != null };
    results.push(res);
    onResult(res, { baseline: b1, baseMillis });
  }
  return results;
}
