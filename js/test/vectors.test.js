import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  sqlInjectionDetector,
  xssDetector,
  pathTraversalDetector,
  commandInjectionDetector,
  inputInspector,
} from '../src/index.js';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../test-vectors');

export function load(file) {
  return fs
    .readFileSync(path.join(dir, file), 'utf8')
    .split(/\r?\n/)
    .filter((l) => l.trim() !== '' && !l.startsWith('# '));
}

const suites = {
  sqli: sqlInjectionDetector,
  xss: xssDetector,
  path: pathTraversalDetector,
  cmd: commandInjectionDetector,
};

for (const [kind, detector] of Object.entries(suites)) {
  test(`${kind}: every malicious vector is detected`, () => {
    const missed = load(`${kind}-malicious.txt`).filter((line) => !detector.inspect(line).malicious);
    assert.deepEqual(missed, []);
  });

  test(`${kind}: no benign vector is flagged`, () => {
    const flagged = load(`${kind}-benign.txt`).filter((line) => detector.inspect(line).malicious);
    assert.deepEqual(flagged, []);
  });
}

test('combined inspector has no false positives on any benign file', () => {
  const flagged = Object.keys(suites)
    .flatMap((k) => load(`${k}-benign.txt`))
    .filter((line) => inputInspector.inspect(line).malicious)
    .map((line) => `${line} -> ${inputInspector.inspect(line).findings.map((f) => f.ruleId)}`);
  assert.deepEqual(flagged, []);
});

// ReDoS guard: adversarial 64 KB inputs must be inspected in linear time. Before the rules were
// bounded, '<a ' repeated took ~420 ms here (~9 s in Java). The limit is generous for slow CI.
for (const unit of ["'", 'or 1=', '<a ', '/*', '${', '%25', '{{', 'nc ', 'a/*', "'/*", 'cast(', '<a on', '&#']) {
  test(`no catastrophic backtracking: 64 KB of '${unit}'`, () => {
    const input = unit.repeat(Math.ceil(65536 / unit.length));
    inputInspector.inspect(input);
    const start = performance.now();
    inputInspector.inspect(input);
    const ms = performance.now() - start;
    assert.ok(ms < 1000, `took ${ms.toFixed(0)} ms`);
  });
}

test('findings carry OWASP category and no input text', () => {
  const r = sqlInjectionDetector.inspect("1;SELECT pg_sleep(5)--");
  assert.ok(r.findings.some((f) => f.ruleId === 'SQLI_PG_SLEEP'));
  assert.equal(r.findings[0].category.id2025, 'A05:2025');
  assert.ok(!JSON.stringify(r).includes('pg_sleep(5)'));
});
