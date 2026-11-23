// Dependency-free micro-benchmark. Each case warms up, then runs ROUNDS timed rounds and
// reports the median time per operation. Run: node bench/bench.js
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  inputInspector,
  sqlInjectionDetector,
  HttpRequestInspector,
  PathTraversalGuard,
  RouteAccessPolicy,
  forHtml,
  PasswordHasher,
} from '../src/index.js';

const ROUNDS = 7;
const ROUND_MS = 300;
let sink = 0;

const repeat = (s, len) => s.repeat(Math.ceil(len / s.length)).slice(0, len);

function format(ns) {
  if (ns >= 1e6) return `${(ns / 1e6).toFixed(1)} ms`;
  if (ns >= 1e3) return `${(ns / 1e3).toFixed(1)} us`;
  return `${ns.toFixed(0)} ns`;
}

async function bench(name, op) {
  const isAsync = op.constructor.name === 'AsyncFunction';
  const run = async () => {
    const r = isAsync ? await op() : op();
    sink += r ? 1 : 0;
  };
  const warmEnd = performance.now() + 2 * ROUND_MS;
  while (performance.now() < warmEnd) await run();
  const perOp = [];
  for (let r = 0; r < ROUNDS; r++) {
    let ops = 0;
    const start = performance.now();
    let now;
    do {
      if (isAsync) await run();
      else sink += op() ? 1 : 0;
      ops++;
      now = performance.now();
    } while (now - start < ROUND_MS);
    perOp.push(((now - start) * 1e6) / ops);
  }
  perOp.sort((a, b) => a - b);
  const median = perOp[Math.floor(ROUNDS / 2)];
  console.log(`| ${name} | ${format(median)} | ${Math.round(1e9 / median).toLocaleString('en-US')} |`);
}

const benign4k = repeat('The quick brown fox jumps over the lazy dog, then orders 3 items. ', 4096);
const benign64k = repeat('The quick brown fox jumps over the lazy dog, then orders 3 items. ', 65536);
const http = new HttpRequestInspector();
const query = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`field${i}`, `value number ${i}`]));
query.email = 'john.smith@example.com';
query.comment = "I'll be there (maybe) -- Ann";
const headers = {
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36',
  referer: 'https://shop.example.com/cart?step=2',
  accept: 'text/html',
};
const guard = PathTraversalGuard.forBaseDirectory(fs.mkdtempSync(path.join(os.tmpdir(), 'bench-')));
const policy = new RouteAccessPolicy().permitAll('GET', '/public/**').hasAnyRole('*', '/admin/**', 'ADMIN').authenticated('*', '/api/**');
const user = { id: 'alice', roles: ['USER'] };
const html1k = repeat('<b>Tom & "Jerry"</b> ', 1024);
const hasher = new PasswordHasher();

console.log(`node ${process.version}, ${os.type()} ${os.arch()}, ${os.cpus().length} cpus`);
console.log('| Case | Median | Ops/s |');
console.log('|---|---:|---:|');

await bench('inspect: short benign value (22 chars)', () => inputInspector.inspect('john.smith@example.com'));
await bench('inspect: benign sentence (61 chars)', () => inputInspector.inspect('Please select an option or two and we will execute the plan'));
await bench('inspect: SQLi payload (pg_sleep stacked)', () => inputInspector.inspect('1;SELECT pg_sleep(5)--'));
await bench('inspect: double-encoded SQLi', () => inputInspector.inspect('%2527%2520OR%25201%253D1--'));
await bench('inspect: PG DO block RAISE EXCEPTION', () => inputInspector.inspect("1';DO $$BEGIN RAISE EXCEPTION '%', (SELECT version()); END$$;--"));
await bench('inspect: 4 KB benign text', () => inputInspector.inspect(benign4k));
await bench('inspect: 64 KB benign text (max inspected)', () => inputInspector.inspect(benign64k));
await bench('sqli only: SQLi payload', () => sqlInjectionDetector.inspect("' OR 1=1--"));
await bench('http: request with 12 params + 3 headers', () => http.inspect({ path: '/api/orders/42', query, headers }));

// Adversarial input aimed at regex backtracking; must stay linear.
await bench('ReDoS probe: 64 KB of single quotes', () => inputInspector.inspect(repeat("'", 65536)));
await bench("ReDoS probe: 64 KB of 'or 1=' repeated", () => inputInspector.inspect(repeat('or 1=', 65536)));
await bench("ReDoS probe: 64 KB of '<a ' repeated", () => inputInspector.inspect(repeat('<a ', 65536)));
await bench("ReDoS probe: 64 KB of '/*' repeated", () => inputInspector.inspect(repeat('/*', 65536)));
await bench("ReDoS probe: 64 KB of '${' repeated", () => inputInspector.inspect(repeat('${', 65536)));
await bench("ReDoS probe: 64 KB of '%25' repeated", () => inputInspector.inspect(repeat('%25', 65536)));

await bench('PathTraversalGuard.resolve (3 segments)', () => guard.resolve('reports/2026/q1.pdf'));
await bench('RouteAccessPolicy.evaluate', () => policy.evaluate('GET', '/api/orders/42', user));
await bench('forHtml (1 KB)', () => forHtml(html1k));
await bench('PasswordHasher.hash (600k iterations)', async () => hasher.hash('correct horse battery'));

if (sink === -1) console.log();
