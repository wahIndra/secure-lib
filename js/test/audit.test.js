import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dgram from 'node:dgram';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  AuditLog, FileAuditSink, SyslogAuditSink, AuditChain, AUDIT_GENESIS, auditRecord, auditRecordOf, formatAuditRecord,
  securityEvent, SecurityEventType, OwaspCategory, LoginAttemptLimiter,
} from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const HMAC_KEY = 'audit-vector-hmac-key-0123456789';

function unescape(s) {
  return s.replace(/\\(u[0-9a-fA-F]{4}|.)/g, (_, e) => (e === 'n' ? '\n' : e === 't' ? '\t' : e[0] === 'u' && e.length === 5 ? String.fromCharCode(parseInt(e.slice(1), 16)) : e));
}

function loadVectors() {
  const text = fs.readFileSync(path.join(here, '../../test-vectors/audit-vectors.txt'), 'utf8');
  return text.split(/\r?\n\r?\n/).map((block) => block.split(/\r?\n/).filter((l) => l && !l.startsWith('#')))
    .filter((lines) => lines.length)
    .map((lines) => Object.fromEntries(lines.map((l) => [l.slice(0, l.indexOf('\t')), l.slice(l.indexOf('\t') + 1)])));
}

function build(c) {
  const v = (k) => (c[k] == null ? undefined : unescape(c[k]));
  if (v('kind') === 'security') {
    const e = securityEvent(v('event'), {
      incidentId: v('incidentId'), method: v('method'), path: v('path'), remoteAddress: v('remoteAddress'),
      principalId: v('principalId'), category: v('category') ? OwaspCategory[v('category')] : undefined,
      ruleIds: v('ruleIds') ? v('ruleIds').split(',') : [], detail: v('detail'),
    });
    return auditRecordOf({ ...e, timestamp: v('timestamp') });
  }
  return auditRecord(v('event'), {
    timestamp: v('timestamp'), incidentId: v('incidentId'), principalId: v('principalId'), remoteAddress: v('remoteAddress'),
    method: v('method'), path: v('path'), resource: v('resource'), detail: v('detail'),
    outcome: v('outcome'), severity: v('severity') ? Number(v('severity')) : undefined,
  });
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secure-audit-'));

test('audit lines are identical to the Java library in every format (shared vectors)', async () => {
  const cases = loadVectors();
  assert.ok(cases.length >= 10);
  const sha = new AuditChain();
  const hmac = new AuditChain(HMAC_KEY);
  let prev = AUDIT_GENESIS;
  let prevHmac = AUDIT_GENESIS;
  for (const c of cases) {
    const r = build(c);
    for (const f of ['json', 'ecs', 'cef']) assert.equal(formatAuditRecord(r, f), c[f], `${c.case} / ${f}`);
    const linked = sha.link(prev, c.json);
    assert.equal(linked, c.chained, `${c.case} / chain`);
    prev = linked.slice(-66, -2);
    const linkedHmac = hmac.link(prevHmac, c.json);
    assert.equal(linkedHmac, c.chainedHmac, `${c.case} / hmac chain`);
    prevHmac = linkedHmac.slice(-66, -2);
  }
});

test('records are sanitized: no line breaks, secrets masked, long values capped', async () => {
  const r = auditRecord('x', { detail: `a\nb password=hunter2 ${'z'.repeat(5000)}`, principalId: 'p\r\nINJECTED' });
  const line = formatAuditRecord(r);
  assert.ok(!line.includes('\n') && !line.includes('\r'));
  assert.ok(!line.includes('hunter2'));
  assert.ok(r.detail.length < 1100);
  assert.throws(() => auditRecord(''), TypeError);
  assert.throws(() => auditRecord('x', { outcome: 'maybe' }), RangeError);
  assert.throws(() => auditRecord('x', { severity: 11 }), RangeError);
  assert.throws(() => formatAuditRecord(r, 'xml'), RangeError);
});

test('file sink appends JSON lines to the chosen path, owner-only, and creates directories', async () => {
  const dir = tmp();
  const file = path.join(dir, 'nested', 'security-audit.jsonl');
  const sink = new FileAuditSink(file);
  sink.write(auditRecord('a', { timestamp: 0 }));
  sink.write(auditRecord('b', { timestamp: 0 }));
  await sink.close();
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[1]).event, 'b');
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('file sink rotates by size and keeps maxFiles', async () => {
  const dir = tmp();
  const file = path.join(dir, 'a.log');
  const sink = new FileAuditSink(file, { maxBytes: 400, maxFiles: 2 });
  for (let i = 0; i < 20; i++) sink.write(auditRecord(`e${i}`, { timestamp: 0, detail: 'x'.repeat(100) }));
  await sink.close();
  assert.ok(fs.existsSync(`${file}.1`) && fs.existsSync(`${file}.2`) && !fs.existsSync(`${file}.3`));
  for (const f of [file, `${file}.1`, `${file}.2`]) assert.ok(fs.statSync(f).size <= 400, f);
  assert.match(fs.readFileSync(file, 'utf8'), /"event":"e19"/);
});

test('hash chain: verify passes, then catches an edited, a removed and a reordered record', async () => {
  const dir = tmp();
  const file = path.join(dir, 'audit.jsonl');
  const sink = new FileAuditSink(file, { hashChain: true });
  for (let i = 0; i < 5; i++) sink.write(auditRecord(`e${i}`, { timestamp: 0 }));
  await sink.close();
  const chain = new AuditChain();
  assert.equal(chain.verify([file]).intact, true);
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');

  fs.writeFileSync(file, `${[...lines.slice(0, 2), lines[2].replace('"e2"', '"e9"'), ...lines.slice(3)].join('\n')}\n`);
  assert.match(chain.verify([file]).problems.join(), /audit.jsonl:3: hash does not match/);

  fs.writeFileSync(file, `${[lines[0], lines[1], lines[3], lines[4]].join('\n')}\n`);
  assert.match(chain.verify([file]).problems.join(), /audit.jsonl:3: does not follow/);

  fs.writeFileSync(file, `${[lines[1], lines[0], ...lines.slice(2)].join('\n')}\n`);
  assert.equal(chain.verify([file]).intact, false);
});

test('hash chain continues across a restart and across rotated files', async () => {
  const dir = tmp();
  const file = path.join(dir, 'audit.jsonl');
  let sink = new FileAuditSink(file, { hashChain: true, maxBytes: 600, maxFiles: 10 });
  for (let i = 0; i < 4; i++) sink.write(auditRecord(`a${i}`, { timestamp: 0 }));
  await sink.close();
  sink = new FileAuditSink(file, { hashChain: true, maxBytes: 600, maxFiles: 10 });
  for (let i = 0; i < 4; i++) sink.write(auditRecord(`b${i}`, { timestamp: 0 }));
  await sink.close();
  const files = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map((n) => `${file}.${n}`).filter((f) => fs.existsSync(f)).concat(file);
  assert.ok(files.length > 1, 'rotated');
  const r = new AuditChain().verify(files);
  assert.equal(r.intact, true, r.problems.join('\n'));
  assert.equal(r.records, 8);
  assert.deepEqual(r.notes, []);
  assert.equal(new AuditChain().verify([file]).notes.length, 1, 'the newest file alone continues an earlier one');
});

test('HMAC chain needs the right key; the chain refuses CEF files', async () => {
  const dir = tmp();
  const file = path.join(dir, 'audit.jsonl');
  const sink = new FileAuditSink(file, { hmacKey: 'k'.repeat(32) });
  sink.write(auditRecord('a'));
  await sink.close();
  assert.equal(new AuditChain('k'.repeat(32)).verify([file]).intact, true);
  assert.equal(new AuditChain('x'.repeat(32)).verify([file]).intact, false);
  assert.equal(new AuditChain().verify([file]).intact, false);
  assert.throws(() => new AuditChain('short'), RangeError);
  assert.throws(() => new FileAuditSink(path.join(dir, 'c.log'), { format: 'cef', hashChain: true }), TypeError);
});

test('secure audit verify: exit 0 intact, 1 tampered, 2 usage', async () => {
  const dir = tmp();
  const file = path.join(dir, 'audit.jsonl');
  const sink = new FileAuditSink(file, { hashChain: true });
  sink.write(auditRecord('a'));
  sink.write(auditRecord('b'));
  await sink.close();
  const cli = path.join(here, '../bin/secure.js');
  const run = (...args) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', stdio: 'pipe' }) };
    } catch (e) {
      return { code: e.status, out: `${e.stdout}${e.stderr}` };
    }
  };
  const ok = run('audit', 'verify', file);
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /2 record\(s\), chain intact/);
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('"a"', '"z"'));
  const bad = run('audit', 'verify', file);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /TAMPERED: audit.jsonl:1/);
  assert.equal(run('audit').code, 2);
  assert.equal(run('audit', 'verify', file, '--key-env', 'SECURE_TEST_UNSET_VAR').code, 2);
});

test('syslog over UDP: RFC 5424 message with CEF body and audit facility', async () => {
  const server = dgram.createSocket('udp4');
  await new Promise((r) => server.bind(0, '127.0.0.1', r));
  const got = new Promise((r) => server.once('message', (m) => r(m.toString('utf8'))));
  const sink = new SyslogAuditSink({ host: '127.0.0.1', port: server.address().port, appName: 'orders api', hostname: 'web-1' });
  await sink.write(auditRecordOf(securityEvent(SecurityEventType.REQUEST_BLOCKED, { incidentId: 'i1', path: '/x' })));
  const msg = await got;
  await sink.close();
  server.close();
  assert.match(msg, /^<108>1 \d{4}-\d\d-\d\dT[\d:.]+Z web-1 orders_api - REQUEST_BLOCKED - CEF:0\|wahindra\|secure\|1\|REQUEST_BLOCKED\|/);
});

test('syslog over TCP: octet-counting framing; reconnects after the server drops', async () => {
  const received = [];
  const sockets = [];
  const server = net.createServer((s) => {
    sockets.push(s);
    s.on('data', (d) => received.push(d.toString('utf8')));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const sink = new SyslogAuditSink({ host: '127.0.0.1', port: server.address().port, protocol: 'tcp', format: 'json' });
  await sink.write(auditRecord('one'));
  await new Promise((r) => setTimeout(r, 50));
  sockets.forEach((s) => s.destroy());
  await new Promise((r) => setTimeout(r, 50));
  // The first write after the drop may fail (counted by AuditLog); the next one reconnects.
  try { await sink.write(auditRecord('lost')); } catch { /* expected */ }
  await sink.write(auditRecord('two'));
  await new Promise((r) => setTimeout(r, 50));
  await sink.close();
  server.close();
  const all = received.join('');
  const m = /^(\d+) </.exec(all);
  assert.ok(m, all.slice(0, 80));
  assert.equal(Buffer.byteLength(all.slice(m[0].length - 1).split(/\d+ </)[0]), Number(m[1]));
  assert.match(all, /"event":"one"/);
  assert.match(all, /"event":"two"/);
});

test('AuditLog never throws or blocks: a failing sink is counted, a full queue drops', async () => {
  const warnings = [];
  const logger = { warn: (m) => warnings.push(m), info: () => {} };
  const written = [];
  let fail = true;
  const flaky = { write: async (r) => { if (fail) throw new Error('disk full'); written.push(r.event); } };
  const audit = new AuditLog({ sinks: [flaky], queueCapacity: 3, logger });
  for (let i = 0; i < 5; i++) audit.record(`e${i}`);
  assert.equal(audit.droppedCount, 2, 'queue of 3');
  await audit.flush();
  assert.equal(audit.failedWriteCount, 3);
  assert.equal(warnings.filter((w) => w.includes('failed: Error: disk full')).length, 1, 'warned once, not per record');
  fail = false;
  assert.equal(audit.record('after'), true);
  await audit.flush();
  assert.deepEqual(written, ['after']);
  assert.equal(audit.record(''), false, 'an invalid record is rejected, not thrown');
  await audit.close();
  assert.equal(audit.record('late'), false);
  assert.throws(() => new AuditLog({ sinks: [] }), TypeError);
});

test('AuditLog as a listener: middleware events and login attempts end up in the file', async () => {
  const dir = tmp();
  const file = path.join(dir, 'audit.jsonl');
  const audit = new AuditLog({ sinks: [new FileAuditSink(file, { hashChain: true })] });
  const limiter = new LoginAttemptLimiter({ maxFailures: 2 }).onLockout(audit.onEvent).onAttempt(audit.onEvent);
  limiter.recordFailure('bob');
  limiter.recordFailure('bob');
  limiter.recordSuccess('alice');
  audit.onEvent(securityEvent(SecurityEventType.ACCESS_DENIED, { principalId: 'mallory', path: '/api/orders/1' }));
  audit.record('order.refund', { principalId: 'alice', resource: 'order/42' });
  await audit.close();
  const events = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l).event);
  assert.deepEqual(events, ['LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_LOCKED', 'LOGIN_SUCCEEDED', 'ACCESS_DENIED', 'order.refund']);
  assert.equal(new AuditChain().verify([file]).intact, true);
});

test('auditFields(req) fills in the user and request details for application events', async () => {
  const { auditFields } = await import('../src/express.js');
  const req = { method: 'POST', originalUrl: '/api/orders/42/refund?x=1', ip: '10.0.0.5', user: { id: 'alice' } };
  const r = auditRecord('order.refund', { ...auditFields(req), resource: 'order/42' });
  assert.equal(r.principalId, 'alice');
  assert.equal(r.path, '/api/orders/42/refund');
  assert.equal(r.remoteAddress, '10.0.0.5');
  assert.equal(auditFields({ method: 'GET', url: '/' }).principalId, undefined);
});
