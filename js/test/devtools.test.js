import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SourceScanner, defaultRules, toSarif, explain, probe, langOf } from '../src/devtools.js';
import { forHtml } from '../src/encode.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(here, '../../test-vectors/scan');
const cli = path.resolve(here, '../bin/secure.js');
const files = (d) => fs.readdirSync(path.join(dir, d)).sort().map((f) => path.join(dir, d, f));

function expectations(file) {
  const expected = {};
  fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, i) => {
    const m = line.match(/expect-next:\s*([A-Z0-9_,\s]+)/);
    if (m) expected[i + 2] = m[1].split(/[,\s]+/).filter(Boolean).sort();
  });
  return expected;
}

for (const file of files('vulnerable')) {
  test(`scanner: ${path.basename(file)} produces exactly the expected findings`, () => {
    const actual = {};
    for (const f of new SourceScanner().scan(file).findings) (actual[f.line] ??= []).push(f.rule.id);
    for (const k of Object.keys(actual)) actual[k].sort();
    assert.deepEqual(actual, expectations(file));
  });
}

for (const file of files('safe')) {
  test(`scanner: safe ${path.basename(file)} produces no findings`, () => {
    assert.deepEqual(new SourceScanner().scan(file).findings.map((f) => `${f.line} ${f.rule.id}`), []);
  });
}

test('scanner: every rule is exercised by a fixture line', () => {
  const covered = new Set(files('vulnerable').flatMap((f) => Object.values(expectations(f)).flat()));
  assert.deepEqual(defaultRules().map((r) => r.id).filter((id) => !covered.has(id)), []);
});

test('scanner: language detection and SARIF output', () => {
  assert.equal(langOf('config/.env.production'), 'config');
  assert.equal(langOf('src/App.tsx'), 'js');
  assert.equal(langOf('notes.txt'), null);
  const sarif = JSON.parse(toSarif(new SourceScanner().scan(path.join(dir, 'vulnerable'))));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.some((r) => r.ruleId === 'SQL_TEMPLATE_LITERAL'));
});

test('cli: scan exit codes, check and probe safety', () => {
  const run = (...args) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', stdio: 'pipe' }) };
    } catch (e) {
      return { code: e.status, out: `${e.stdout}${e.stderr}` };
    }
  };
  assert.equal(run('scan', path.join(dir, 'vulnerable')).code, 1);
  assert.equal(run('scan', path.join(dir, 'safe')).code, 0);
  assert.equal(run('scan', '--fail-on', 'none', path.join(dir, 'vulnerable')).code, 0);
  assert.equal(run('scan', '--format', 'xml').code, 2);
  const c = run('check', '%27%20OR%201%3D1--');
  assert.equal(c.code, 1);
  assert.match(c.out, /decoded {3}: ' or 1=1--/);
  assert.match(c.out, /SQLI_BOOLEAN_TAUTOLOGY/);
  assert.equal(run('check', "O'Brien").code, 0);
  const p = run('probe', 'http://93.184.215.14/?q=FUZZ');
  assert.equal(p.code, 2);
  assert.match(p.out, /only targets local\/private servers/);
});

test('explain matches the Java check output', () => {
  const e = explain("1';DO $$BEGIN RAISE EXCEP/**/TION '%', (SELECT version()); END$$;--");
  assert.equal(e.malicious, true);
  assert.ok(e.findings.some((f) => f.ruleId === 'SQLI_PG_DO_BLOCK'));
  assert.equal(explain("O'Brien").verdict, 'clean');
});

// ---------------------------------------------------------------- probe against a vulnerable local server

let server;
let base;
before(async () => {
  server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const v = url.searchParams.get('q') ?? url.searchParams.get('id') ?? url.searchParams.get('name') ?? '';
    const send = (status, body) => { res.writeHead(status); res.end(body); };
    if (url.pathname === '/search') {
      const m = v.match(/^\{\{(\d+)\*(\d+)\}\}$/);
      return send(200, m ? `<p>${Number(m[1]) * Number(m[2])}</p>` : `<p>Results for ${v}</p>`); // reflected XSS, SSTI
    }
    if (url.pathname === '/item') {
      if (v.startsWith('1;SELECT pg_sleep(3)')) await new Promise((r) => setTimeout(r, 3000));
      return v.includes("'") ? send(500, 'error: unterminated quoted string at or near "\'"') : send(200, '{"id":1}');
    }
    if (url.pathname === '/file') return v.includes('etc/passwd') ? send(200, 'root:x:0:0:root:/root:/bin/bash\n') : send(404, 'no');
    return send(200, `<p>Results for ${forHtml(v)}</p>`); // /safe
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const hits = async (t) => new Set((await probe(t)).filter((r) => r.vulnerable).map((r) => r.check));

test('probe finds reflected XSS and template injection', async () => {
  const h = await hits({ url: `${base}/search?q=FUZZ`, only: ['xss', 'ssti'] });
  assert.ok(h.has('xss') && h.has('ssti'), [...h].join());
});

test('probe finds error-based and time-based SQL injection', async () => {
  const r = await probe({ url: `${base}/item?id=FUZZ`, only: ['sqli'] });
  const high = new Set(r.filter((x) => x.severity === 'HIGH').map((x) => x.check));
  assert.ok(high.has('sqli-error') && high.has('sqli-time'), [...high].join());
});

test('probe finds path traversal', async () => {
  assert.ok((await hits({ url: `${base}/file?name=FUZZ`, only: ['path'] })).has('path'));
});

test('probe reports nothing for the safe endpoint', async () => {
  assert.deepEqual([...(await hits({ url: `${base}/safe?q=FUZZ` }))], []);
});
