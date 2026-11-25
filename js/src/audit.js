// Audit log: security events and application actions, written to a file, a syslog / SIEM
// collector, or your own sink. Same records, formats and hash chain as the Java library
// (io.github.wahindra.secure.audit); test-vectors/audit-vectors.json keeps them identical.

import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { sanitizeForLog } from './log.js';

export const AuditOutcome = Object.freeze({
  SUCCESS: 'success', FAILURE: 'failure', DENIED: 'denied', BLOCKED: 'blocked', FLAGGED: 'flagged', ERROR: 'error',
});

const OUTCOMES = new Set(Object.values(AuditOutcome));
const clean = (v, max) => (v == null ? undefined : sanitizeForLog(String(v), max));

const SECURITY_OUTCOME = {
  REQUEST_BLOCKED: 'blocked', REQUEST_FLAGGED: 'flagged', LOGIN_FAILED: 'failure', LOGIN_SUCCEEDED: 'success', INSPECTION_ERROR: 'error',
};
const SECURITY_SEVERITY = {
  REQUEST_BLOCKED: 7, LOGIN_LOCKED: 7, INSPECTION_ERROR: 6, REQUEST_FLAGGED: 5, ACCESS_DENIED: 5, RATE_LIMITED: 4, CORS_REJECTED: 4,
};
const OUTCOME_SEVERITY = { blocked: 7, error: 6, denied: 5, flagged: 5, failure: 3, success: 1 };

function makeRecord(kind, event, o) {
  const outcome = o.outcome ?? 'success';
  if (!OUTCOMES.has(outcome)) throw new RangeError(`outcome must be one of ${[...OUTCOMES].join(', ')}`);
  let severity = o.severity;
  if (severity == null) severity = (kind === 'security' && SECURITY_SEVERITY[event]) || OUTCOME_SEVERITY[outcome];
  else if (!Number.isInteger(severity) || severity < 0 || severity > 10) throw new RangeError('severity must be 0..10');
  const ts = o.timestamp == null ? new Date() : new Date(o.timestamp);
  if (Number.isNaN(ts.getTime())) throw new RangeError('invalid timestamp');
  return Object.freeze({
    timestamp: ts.toISOString(),
    kind,
    event: clean(event, 100),
    outcome,
    severity,
    incidentId: clean(o.incidentId ?? crypto.randomUUID(), 64),
    principalId: clean(o.principalId, 128),
    remoteAddress: clean(o.remoteAddress, 64),
    method: clean(o.method, 16),
    path: clean(o.path, 300),
    resource: clean(o.resource, 300),
    owasp: clean(o.owasp, 16),
    category: clean(o.category, 100),
    ruleIds: Object.freeze((o.ruleIds ?? []).filter((r) => r != null).map((r) => clean(r, 100))),
    detail: clean(o.detail, 1000),
  });
}

/**
 * An application action, e.g. `auditRecord('order.refund', { principalId, resource: 'order/42' })`.
 * Outcome defaults to `success`. All text is sanitized; never put passwords or tokens in `detail`.
 */
export function auditRecord(event, { outcome, severity, timestamp, incidentId, principalId, remoteAddress, method, path: p, resource, owasp, category, ruleIds, detail } = {}) {
  if (typeof event !== 'string' || !event.trim()) throw new TypeError('event name is required, e.g. "order.refund"');
  return makeRecord('application', event.trim(), { outcome, severity, timestamp, incidentId, principalId, remoteAddress, method, path: p, resource, owasp, category, ruleIds, detail });
}

/** The audit record for a library security event (from `securityEvent()`). */
export function auditRecordOf(event) {
  return makeRecord('security', event.type, {
    outcome: SECURITY_OUTCOME[event.type] ?? 'denied',
    timestamp: event.timestamp,
    incidentId: event.incidentId,
    principalId: event.principalId,
    remoteAddress: event.remoteAddress,
    method: event.method,
    path: event.path,
    owasp: event.owasp,
    category: event.category,
    ruleIds: event.ruleIds,
    detail: event.detail,
  });
}

// ---------------------------------------------------------------- formats

const IP = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$/;
const isIp = (s) => IP.test(s);

/** JSON string, escaped exactly like the Java writer: `"` and `\`, controls and lone surrogates as \uXXXX. */
function quote(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22 || c === 0x5c) out += `\\${s[i]}`;
    else if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff && !validSurrogate(s, i))) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += s[i];
  }
  return `${out}"`;
}

function validSurrogate(s, i) {
  const c = s.charCodeAt(i);
  if (c <= 0xdbff) {
    const n = s.charCodeAt(i + 1);
    return n >= 0xdc00 && n <= 0xdfff;
  }
  const p = s.charCodeAt(i - 1);
  return i > 0 && p >= 0xd800 && p <= 0xdbff;
}

/** Minimal JSON writer matching the Java one: fixed field order, nulls and empty objects left out. */
class Json {
  #parts = [];
  #stack = [];
  str(name, value) { if (value != null) this.#parts.push(`${quote(name)}:${quote(value)}`); return this; }
  num(name, value) { this.#parts.push(`${quote(name)}:${value}`); return this; }
  arr(name, values) { if (values?.length) this.#parts.push(`${quote(name)}:[${values.map(quote).join(',')}]`); return this; }
  open(name) { this.#stack.push([name, this.#parts]); this.#parts = []; return this; }
  close() {
    const inner = this.#parts;
    const [name, outer] = this.#stack.pop();
    this.#parts = outer;
    if (inner.length) outer.push(`${quote(name)}:{${inner.join(',')}}`);
    return this;
  }
  end() { return `{${this.#parts.join(',')}}`; }
}

function ecsCategory(r) {
  if (r.kind !== 'security') return undefined;
  if (r.event.startsWith('LOGIN_')) return ['authentication'];
  if (r.event === 'REQUEST_BLOCKED' || r.event === 'REQUEST_FLAGGED') return ['intrusion_detection', 'web'];
  return ['web'];
}
const ECS_TYPE = { blocked: 'denied', denied: 'denied', success: 'allowed', error: 'error' };
const ECS_OUTCOME = { success: 'success', failure: 'failure', denied: 'failure', blocked: 'failure' };
const CEF_NAME = {
  REQUEST_BLOCKED: 'Malicious request blocked',
  REQUEST_FLAGGED: 'Suspicious request flagged',
  RATE_LIMITED: 'Rate limit exceeded',
  CORS_REJECTED: 'CORS request rejected',
  ACCESS_DENIED: 'Access denied',
  LOGIN_LOCKED: 'Account locked out',
  LOGIN_FAILED: 'Login failed',
  LOGIN_SUCCEEDED: 'Login succeeded',
  INSPECTION_ERROR: 'Request inspection failed',
};
const cefHeader = (s) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const cefValue = (s) => s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r/g, '\\r').replace(/\n/g, '\\n');

/** One line per record, without a terminator. Output is identical to the Java library's. */
export const AuditFormat = Object.freeze({
  JSON: 'json',
  ECS: 'ecs',
  CEF: 'cef',
});

export function formatAuditRecord(r, format = 'json') {
  switch (String(format).toLowerCase()) {
    case 'json': {
      return new Json().str('timestamp', r.timestamp).str('kind', r.kind).str('event', r.event).str('outcome', r.outcome)
        .num('severity', r.severity).str('incidentId', r.incidentId).str('principalId', r.principalId)
        .str('remoteAddress', r.remoteAddress).str('method', r.method).str('path', r.path).str('resource', r.resource)
        .str('owasp', r.owasp).str('category', r.category).arr('ruleIds', r.ruleIds).str('detail', r.detail).end();
    }
    case 'ecs': {
      const j = new Json().str('@timestamp', r.timestamp).open('ecs').str('version', '8.11.0').close();
      j.open('event').str('kind', r.outcome === 'blocked' || r.outcome === 'flagged' ? 'alert' : 'event')
        .arr('category', ecsCategory(r)).arr('type', [ECS_TYPE[r.outcome] ?? 'info']).str('action', r.event)
        .str('outcome', ECS_OUTCOME[r.outcome] ?? 'unknown').num('severity', r.severity).str('id', r.incidentId).close();
      j.open('user').str('id', r.principalId).close();
      if (r.remoteAddress != null) j.open('source').str(isIp(r.remoteAddress) ? 'ip' : 'address', r.remoteAddress).close();
      j.open('http').open('request').str('method', r.method).close().close();
      j.open('url').str('path', r.path).close();
      j.open('rule').arr('id', r.ruleIds).close();
      j.open('labels').str('audit_kind', r.kind).str('audit_outcome', r.outcome).str('resource', r.resource)
        .str('owasp', r.owasp).str('owasp_category', r.category).close();
      return j.str('message', r.detail).end();
    }
    case 'cef': {
      const ext = [];
      const add = (k, v) => { if (v != null) ext.push(`${k}=${cefValue(String(v))}`); };
      add('rt', Date.parse(r.timestamp));
      add('outcome', r.outcome);
      add('externalId', r.incidentId);
      add('suser', r.principalId);
      if (r.remoteAddress != null) add(isIp(r.remoteAddress) ? 'src' : 'shost', r.remoteAddress);
      add('requestMethod', r.method);
      add('request', r.path);
      if (r.owasp != null) { add('cs1Label', 'owasp'); add('cs1', r.owasp); }
      if (r.ruleIds.length) { add('cs2Label', 'rules'); add('cs2', r.ruleIds.join(',')); }
      if (r.resource != null) { add('cs3Label', 'resource'); add('cs3', r.resource); }
      add('cs4Label', 'kind');
      add('cs4', r.kind);
      add('msg', r.detail);
      const name = (r.kind === 'security' && CEF_NAME[r.event]) || r.event;
      return `CEF:0|wahindra|secure|1|${cefHeader(r.event)}|${cefHeader(name)}|${r.severity}|${ext.join(' ')}`;
    }
    default:
      throw new RangeError(`unknown audit format: ${format} (json, ecs or cef)`);
  }
}

// ---------------------------------------------------------------- hash chain

export const AUDIT_GENESIS = '0'.repeat(64);
const SUFFIX = /,"prev":"([0-9a-f]{64})","hash":"([0-9a-f]{64})"\}$/;

/**
 * Tamper evidence for JSON audit lines: each line ends with `prev` (hash of the line before) and
 * `hash`, SHA-256 or HMAC-SHA256 over `prev + "\n" + line`. Same algorithm as the Java library.
 */
export class AuditChain {
  #key;

  constructor(key = null) {
    if (key != null && Buffer.byteLength(key) < 16) throw new RangeError('HMAC key must be at least 16 bytes');
    this.#key = key == null ? null : Buffer.from(key);
  }

  hash(prev, line) {
    const h = this.#key ? crypto.createHmac('sha256', this.#key) : crypto.createHash('sha256');
    return h.update(`${prev}\n${line}`, 'utf8').digest('hex');
  }

  link(prev, line) {
    if (!line.startsWith('{') || !line.endsWith('}')) throw new TypeError('the hash chain needs JSON lines (format json or ecs)');
    return `${line.slice(0, -1)},"prev":"${prev}","hash":"${this.hash(prev, line)}"}`;
  }

  /** Checks files, oldest first. `{ intact, records, problems, notes, lastHash }`. */
  verify(files) {
    const problems = [];
    const notes = [];
    let last = null;
    let records = 0;
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split('\n');
      if (lines.at(-1) === '') lines.pop();
      lines.forEach((raw, idx) => {
        const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
        if (!line) return;
        records++;
        const where = `${path.basename(file)}:${idx + 1}: `;
        const m = SUFFIX.exec(line);
        if (!m) {
          problems.push(`${where}no hash: written without the chain, cut off, or edited`);
          last = null;
          return;
        }
        const [, prev, hash] = m;
        const base = `${line.slice(0, m.index)}}`;
        if (this.hash(prev, base) !== hash) {
          problems.push(`${where}hash does not match: this record was changed${this.#key ? ' (or the key is wrong)' : ''}`);
        } else if (last == null && records === 1 && prev !== AUDIT_GENESIS) {
          notes.push(`${where}continues an earlier file (prev ${prev.slice(0, 12)}...)`);
        } else if (prev === AUDIT_GENESIS && records > 1) {
          notes.push(`${where}the chain starts again here (log reopened without the previous hash)`);
        } else if (last != null && prev !== last) {
          problems.push(`${where}does not follow the previous record: records before it were removed or reordered`);
        }
        last = hash;
      });
    }
    return { intact: problems.length === 0, records, problems, notes, lastHash: last };
  }
}

const hashOf = (line) => SUFFIX.exec(line)?.[2] ?? null;

// ---------------------------------------------------------------- sinks

function lastHash(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return null;
  }
  try {
    const size = fs.fstatSync(fd).size;
    const n = Math.min(size, 64 * 1024);
    const buf = Buffer.alloc(n);
    fs.readSync(fd, buf, 0, n, size - n);
    const text = buf.toString('utf8').trim();
    return hashOf(text.slice(text.lastIndexOf('\n') + 1).trim());
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Appends one line per record to a file you choose, rotating by size (`name.1` ... `name.N`).
 * New files are created with mode 0600 (owner only) on POSIX systems.
 */
export class FileAuditSink {
  #fd;
  #size;
  #prev;
  #chain;

  constructor(file, { format = 'json', maxBytes = 10 * 1024 * 1024, maxFiles = 10, hashChain = false, hmacKey = null } = {}) {
    if (!file) throw new TypeError('file path is required');
    if (!(maxBytes >= 0) || !(Number.isInteger(maxFiles) && maxFiles >= 0)) throw new RangeError('maxBytes and maxFiles must be >= 0');
    this.path = path.resolve(file);
    this.format = String(format).toLowerCase();
    formatAuditRecord(auditRecord('x'), this.format); // validates the format name
    Object.assign(this, { maxBytes, maxFiles });
    if (hashChain || hmacKey != null) {
      if (this.format === 'cef') throw new TypeError('the hash chain needs JSON lines: use format json or ecs for the file');
      this.#chain = new AuditChain(hmacKey);
      this.#prev = lastHash(this.path) ?? lastHash(this.#rotated(1)) ?? AUDIT_GENESIS;
    }
    fs.mkdirSync(path.dirname(this.path), { recursive: true });
    this.#open();
  }

  #tail = Promise.resolve();

  /**
   * Appends a record. Asynchronous, so a slow disk never stalls the event loop; calls are
   * written one after the other in call order.
   */
  write(record) {
    const line = formatAuditRecord(record, this.format);
    const run = this.#tail.then(() => this.#append(line));
    this.#tail = run.catch(() => {});
    return run;
  }

  async #append(base) {
    if (this.#fd == null) throw new Error('audit file is closed');
    const line = this.#chain ? this.#chain.link(this.#prev, base) : base;
    const bytes = Buffer.from(`${line}\n`, 'utf8');
    if (this.maxBytes > 0 && this.#size > 0 && this.#size + bytes.length > this.maxBytes) this.#rotate();
    let off = 0;
    while (off < bytes.length) {
      off += await new Promise((resolve, reject) => {
        fs.write(this.#fd, bytes, off, bytes.length - off, null, (e, n) => (e ? reject(e) : resolve(n)));
      });
    }
    this.#size += bytes.length;
    if (this.#chain) this.#prev = hashOf(line);
  }

  /** Waits for pending writes, then closes the file. */
  async close() {
    await this.#tail;
    if (this.#fd != null) fs.closeSync(this.#fd);
    this.#fd = null;
  }

  #open() {
    this.#fd = fs.openSync(this.path, 'a', 0o600);
    this.#size = fs.fstatSync(this.#fd).size;
  }

  #rotated(n) {
    return `${this.path}.${n}`;
  }

  #rotate() {
    fs.closeSync(this.#fd);
    fs.rmSync(this.#rotated(this.maxFiles), { force: true });
    for (let i = this.maxFiles - 1; i >= 1; i--) {
      if (fs.existsSync(this.#rotated(i))) fs.renameSync(this.#rotated(i), this.#rotated(i + 1));
    }
    if (this.maxFiles > 0) fs.renameSync(this.path, this.#rotated(1));
    else fs.rmSync(this.path, { force: true });
    this.#open();
  }
}

const printable = (s, max) => {
  if (!s) return '-';
  let out = '';
  for (const c of String(s)) {
    if (out.length >= max) break;
    const code = c.codePointAt(0);
    out += code > 32 && code < 127 ? c : '_';
  }
  return out;
};
const syslogSeverity = (cef) => (cef >= 9 ? 2 : cef >= 7 ? 4 : cef >= 5 ? 5 : 6);

/**
 * Sends records to a syslog server or SIEM as RFC 5424 messages over `udp`, `tcp` or `tls`
 * (RFC 5425 octet counting on TCP and TLS). TLS checks the certificate and host name.
 */
export class SyslogAuditSink {
  #udp = null;
  #socket = null;

  constructor({ host, port, protocol = 'udp', format = 'cef', appName = 'secure', hostname = os.hostname(), facility = 13, connectTimeoutMs = 5000, tlsOptions = {} } = {}) {
    if (!host || !(Number.isInteger(port) && port >= 1 && port <= 65535)) throw new TypeError('syslog host and port (1-65535) are required');
    if (!['udp', 'tcp', 'tls'].includes(protocol)) throw new RangeError('protocol must be udp, tcp or tls');
    if (!(Number.isInteger(facility) && facility >= 0 && facility <= 23)) throw new RangeError('facility must be 0..23');
    formatAuditRecord(auditRecord('x'), format);
    Object.assign(this, { host, port, protocol, format, appName: printable(appName, 48), hostname: printable(hostname, 255), facility, connectTimeoutMs, tlsOptions });
  }

  /** The RFC 5424 message for a record (without TCP framing). */
  message(r) {
    const pri = this.facility * 8 + syslogSeverity(r.severity);
    return `<${pri}>1 ${r.timestamp} ${this.hostname} ${this.appName} - ${printable(r.event, 32)} - ${formatAuditRecord(r, this.format)}`;
  }

  async write(record) {
    const msg = Buffer.from(this.message(record), 'utf8');
    try {
      if (this.protocol === 'udp') {
        this.#udp ??= dgram.createSocket(net.isIPv6(this.host) ? 'udp6' : 'udp4');
        await new Promise((resolve, reject) => this.#udp.send(msg, this.port, this.host, (e) => (e ? reject(e) : resolve())));
        return;
      }
      if (!this.#socket) this.#socket = await this.#connect();
      const framed = Buffer.concat([Buffer.from(`${msg.length} `, 'ascii'), msg]);
      await new Promise((resolve, reject) => this.#socket.write(framed, (e) => (e ? reject(e) : resolve())));
    } catch (e) {
      this.close();
      throw e;
    }
  }

  close() {
    this.#udp?.close();
    this.#udp = null;
    this.#socket?.destroy();
    this.#socket = null;
  }

  #connect() {
    return new Promise((resolve, reject) => {
      const opts = { host: this.host, port: this.port };
      const s = this.protocol === 'tls'
        ? tls.connect({ ...this.tlsOptions, ...opts, servername: net.isIP(this.host) ? undefined : this.host, rejectUnauthorized: true })
        : net.connect(opts);
      const timer = setTimeout(() => s.destroy(new Error(`syslog connect timeout after ${this.connectTimeoutMs} ms`)), this.connectTimeoutMs);
      s.once(this.protocol === 'tls' ? 'secureConnect' : 'connect', () => {
        clearTimeout(timer);
        s.on('error', () => { if (this.#socket === s) this.#socket = null; });
        s.on('close', () => { if (this.#socket === s) this.#socket = null; });
        resolve(s);
      });
      s.once('error', (e) => { clearTimeout(timer); reject(e); });
    });
  }
}

// ---------------------------------------------------------------- the log

/**
 * Audit trail. `record()` never blocks and never throws: records go into a bounded queue, written
 * in the background one at a time. When the queue is full, records are dropped and counted.
 *
 *   const audit = new AuditLog({ sinks: [new FileAuditSink('/var/log/app/security-audit.jsonl', { hashChain: true })] });
 *   app.use(securityMiddleware({ onEvent: audit.onEvent }));
 *   new LoginAttemptLimiter().onLockout(audit.onEvent).onAttempt(audit.onEvent);
 *   audit.record('order.refund', { principalId: req.user.id, resource: `order/${id}` });
 */
export class AuditLog {
  #queue = [];
  #draining = null;
  #failing = new Set();
  #closed = false;
  #dropped = 0;
  #failedWrites = 0;

  constructor({ sinks = [], queueCapacity = 10_000, logger = console } = {}) {
    if (!sinks.length) throw new TypeError('add at least one sink: FileAuditSink, SyslogAuditSink or your own { write(record) }');
    if (!(Number.isInteger(queueCapacity) && queueCapacity >= 1)) throw new RangeError('queueCapacity must be >= 1');
    this.sinks = [...sinks];
    this.queueCapacity = queueCapacity;
    this.logger = logger;
    /** A security event listener: pass it as `onEvent` to the middleware, `onLockout`, `onAttempt`. */
    this.onEvent = (event) => this.record(auditRecordOf(event));
  }

  /**
   * Queues a record: an `auditRecord(...)`, or an event name and its fields.
   * @returns false if it was dropped
   */
  record(recordOrEvent, fields) {
    let r;
    try {
      r = typeof recordOrEvent === 'string' ? auditRecord(recordOrEvent, fields) : recordOrEvent;
    } catch (e) {
      this.#warn(`audit record rejected: ${e.message}`);
      return false;
    }
    if (!r) return false;
    if (this.#closed || this.#queue.length >= this.queueCapacity) {
      this.#dropped++;
      if (this.#dropped === 1 || this.#dropped % 1000 === 0) {
        this.#warn(`audit log: ${this.#dropped} record(s) dropped so far (${this.#closed ? 'closed' : 'queue full'})`);
      }
      return false;
    }
    this.#queue.push(r);
    // Start writing on the next tick, so a burst of records is queued (and capped) as one batch.
    this.#draining ??= Promise.resolve().then(() => this.#drain());
    return true;
  }

  /** Resolves when everything queued so far has been written. */
  async flush() {
    while (this.#draining) await this.#draining;
  }

  /** Writes what is queued, then closes the sinks. Later records are dropped. */
  async close() {
    this.#closed = true;
    await this.flush();
    for (const s of this.sinks) {
      try {
        await s.close?.();
      } catch (e) {
        this.#warn(`audit sink failed to close: ${e?.name ?? 'Error'}`);
      }
    }
  }

  get droppedCount() { return this.#dropped; }
  get failedWriteCount() { return this.#failedWrites; }
  get queued() { return this.#queue.length; }

  async #drain() {
    try {
      while (this.#queue.length) {
        const r = this.#queue.shift();
        for (const s of this.sinks) {
          try {
            await s.write(r);
            if (this.#failing.delete(s)) this.#info(`audit sink ${s.constructor?.name ?? 'sink'} is writing again`);
          } catch (e) {
            this.#failedWrites++;
            if (!this.#failing.has(s)) {
              this.#failing.add(s);
              this.#warn(`audit sink ${s.constructor?.name ?? 'sink'} failed: ${e?.code ?? e?.name ?? 'Error'}: ${e?.message ?? ''} (records are counted and dropped until it recovers)`);
            }
          }
        }
      }
    } finally {
      this.#draining = null;
    }
  }

  #warn(msg) { (this.logger?.warn ?? this.logger?.log)?.call(this.logger, msg); }
  #info(msg) { (this.logger?.info ?? this.logger?.log)?.call(this.logger, msg); }
}
