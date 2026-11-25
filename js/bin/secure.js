#!/usr/bin/env node
// secure: developer tools for @wahindra/secure. Run `secure help` for usage.
import fs from 'node:fs';
import { SourceScanner, DEFAULT_EXCLUDED_DIRS, defaultRules, atLeast, toText, toJson, toSarif, explain, probe, idorProbe } from '../src/devtools.js';
import { AuditChain } from '../src/audit.js';

const USAGE = `secure: developer tools for the secure library

  scan [paths...]           Find vulnerable code patterns (default path: .)
      --fail-on high|medium|low|none   exit 1 when findings at this level exist (default high)
      --format text|json|sarif         text is clickable path:line:col in IDE terminals
      --output FILE                    write the report to FILE
      --exclude DIR                    skip a directory name (repeatable)
      --no-fix                         omit fix hints in text output
  check "<value>" ...       Show how the request filter sees a value and which rules match
  probe <url-with-FUZZ>     Send attack payloads to YOUR local app and report what got through
      -X, --method METHOD              default GET (POST when --data is given)
      -d, --data BODY                  form or JSON body containing FUZZ
      -H, --header 'Name: value'       extra header (repeatable; may contain FUZZ)
      --only sqli,xss,path,cmd,ssti    limit the checks
      --baseline VALUE                 benign value for the baseline request (default 1)
      --timeout SECONDS                per request (default 15)
      --allow-remote                   allow non-local targets you are authorized to test
  idor <object-url>         Check that only the owner can fetch an object (IDOR / BOLA)
      --as-owner 'Header: value'       credentials of the object's owner (any login: bearer, cookie, API key)
      --as-other 'Header: value'       credentials of a different ordinary user
      --marker TEXT                    text only the owner's data contains, for an exact verdict
      -X, --method / -d, --data        as for probe
      --no-anonymous                   skip the request without credentials
      --allow-remote                   allow non-local targets you are authorized to test
  audit verify <file>...    Check an audit log's hash chain (oldest file first)
      --key-env NAME                   HMAC key from this environment variable
  rules                     List the scan rules

Exit codes: 0 ok, 1 findings, 2 usage error.
`;

class UsageError extends Error {}

function value(args, i, option) {
  if (i >= args.length) throw new UsageError(`${option} needs a value`);
  return args[i];
}

function scan(args) {
  let failOn = 'HIGH';
  let format = 'text';
  let output = null;
  let withFix = true;
  const excluded = new Set(DEFAULT_EXCLUDED_DIRS);
  const paths = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--fail-on') failOn = value(args, ++i, a).toUpperCase();
    else if (a === '--format') format = value(args, ++i, a);
    else if (a === '--output' || a === '-o') output = value(args, ++i, a);
    else if (a === '--exclude') excluded.add(value(args, ++i, a));
    else if (a === '--no-fix') withFix = false;
    else if (a.startsWith('-')) throw new UsageError(`unknown option ${a}`);
    else paths.push(a);
  }
  if (!['HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(failOn)) throw new UsageError('--fail-on must be high, medium, low or none');
  const render = { text: (r) => toText(r, { withFix }), json: toJson, sarif: toSarif }[format];
  if (!render) throw new UsageError('--format must be text, json or sarif');
  const report = new SourceScanner({ excludedDirs: excluded }).scan(...paths);
  const out = render(report);
  if (output) {
    fs.writeFileSync(output, out);
    console.log(`wrote ${output}: ${report.findings.length} finding(s)`);
  } else {
    process.stdout.write(out.endsWith('\n') ? out : `${out}\n`);
  }
  return failOn !== 'NONE' && atLeast(report.findings, failOn).length ? 1 : 0;
}

function check(args) {
  if (!args.length) throw new UsageError('usage: check "<value>" ["<value>"...]');
  let any = false;
  for (const v of args) {
    const e = explain(v);
    console.log(`input     : ${e.input}`);
    if (e.decoded !== e.input) console.log(`decoded   : ${e.decoded}`);
    if (e.stripped !== e.decoded) console.log(`stripped  : ${e.stripped}`);
    console.log(`verdict   : ${e.verdict}  score=${e.score} (block at ${e.threshold})`);
    for (const f of e.findings) console.log(`  ${f.severity.padEnd(6)} ${f.ruleId.padEnd(28)} ${f.description}  [${f.category.id2025}]`);
    console.log();
    any ||= e.malicious;
  }
  return any ? 1 : 0;
}

async function probeCmd(args) {
  const t = { headers: {}, only: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!t.url && !a.startsWith('-')) {
      t.url = a;
      continue;
    }
    if (!t.url) throw new UsageError('the target URL must come first');
    if (a === '--method' || a === '-X') t.method = value(args, ++i, a).toUpperCase();
    else if (a === '--data' || a === '-d') t.body = value(args, ++i, a);
    else if (a === '--header' || a === '-H') {
      const h = value(args, ++i, a);
      const colon = h.indexOf(':');
      if (colon <= 0) throw new UsageError("--header expects 'Name: value'");
      t.headers[h.slice(0, colon).trim()] = h.slice(colon + 1).trim();
    } else if (a === '--baseline') t.baseline = value(args, ++i, a);
    else if (a === '--only') t.only.push(...value(args, ++i, a).split(',').map((s) => s.trim()));
    else if (a === '--allow-remote') t.allowRemote = true;
    else if (a === '--timeout') t.timeoutMs = Number(value(args, ++i, a)) * 1000;
    else throw new UsageError(`unknown option ${a}`);
  }
  if (!t.url) throw new UsageError('usage: probe "http://localhost:3000/path?param=FUZZ" [options]');
  let first = true;
  const results = await probe(t, (r, { baseline, baseMillis }) => {
    if (first) {
      console.log(`baseline: HTTP ${baseline.status}, ${baseline.body.length} bytes, ${baseMillis} ms`);
      first = false;
    }
    const p = r.payload.length > 46 ? `${r.payload.slice(0, 43)}...` : r.payload;
    console.log(`${(r.severity ?? 'ok').padEnd(7)} ${r.check.padEnd(10)} HTTP ${String(r.status).padStart(3)} ${String(r.millis).padStart(6)} ms  ${p.padEnd(46)} ${r.verdict}`);
  });
  const high = results.filter((r) => r.severity === 'HIGH').length;
  const medium = results.filter((r) => r.severity === 'MEDIUM').length;
  const blocked = results.filter((r) => r.verdict.startsWith('blocked')).length;
  console.log(`\n${results.length} payloads sent: ${high} HIGH, ${medium} MEDIUM, ${blocked} blocked by the secure filter.`);
  if (high + medium) console.log('Fix the code paths above (see README: How to use), then probe again.');
  return high + medium ? 1 : 0;
}

async function idorCmd(args) {
  const t = { owner: {}, other: {} };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!t.url && !a.startsWith('-')) {
      t.url = a;
      continue;
    }
    if (!t.url) throw new UsageError('the object URL must come first');
    if (a === '--as-owner' || a === '--as-other') {
      const h = value(args, ++i, a);
      const colon = h.indexOf(':');
      if (colon <= 0) throw new UsageError(`${a} expects 'Header-Name: value'`);
      t[a === '--as-owner' ? 'owner' : 'other'][h.slice(0, colon).trim()] = h.slice(colon + 1).trim();
    } else if (a === '--method' || a === '-X') t.method = value(args, ++i, a).toUpperCase();
    else if (a === '--data' || a === '-d') t.body = value(args, ++i, a);
    else if (a === '--marker') t.marker = value(args, ++i, a);
    else if (a === '--no-anonymous') t.anonymous = false;
    else if (a === '--allow-remote') t.allowRemote = true;
    else if (a === '--timeout') t.timeoutMs = Number(value(args, ++i, a)) * 1000;
    else throw new UsageError(`unknown option ${a}`);
  }
  if (!t.url) throw new UsageError("usage: idor <object-url> --as-owner 'Header: value' --as-other 'Header: value'");
  const results = await idorProbe(t);
  for (const r of results) {
    console.log(`${(r.severity ?? 'ok').padEnd(7)} ${r.as.padEnd(15)} HTTP ${String(r.status).padStart(3)}  ${r.verdict}`);
  }
  return results.some((r) => r.severity === 'HIGH' || r.severity === 'MEDIUM') ? 1 : 0;
}

function auditCmd(args) {
  if (args[0] !== 'verify') throw new UsageError('usage: audit verify <file>... [--key-env NAME]');
  const files = [];
  let key = null;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--key-env') {
      const name = value(args, ++i, '--key-env');
      if (!process.env[name]) throw new UsageError(`environment variable ${name} is not set`);
      key = Buffer.from(process.env[name], 'utf8');
    } else {
      files.push(args[i]);
    }
  }
  if (!files.length) throw new UsageError('usage: audit verify <file>... [--key-env NAME] (oldest file first)');
  const r = new AuditChain(key).verify(files);
  for (const n of r.notes) console.log(`note: ${n}`);
  for (const p of r.problems) console.log(`TAMPERED: ${p}`);
  console.log(`${r.records} record(s), ${r.intact ? 'chain intact' : `${r.problems.length} problem(s)`}${r.lastHash ? `; last hash ${r.lastHash}` : ''}`);
  return r.intact ? 0 : 1;
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || ['help', '--help', '-h'].includes(cmd)) {
    process.stdout.write(USAGE);
    return cmd ? 0 : 2;
  }
  if (cmd === 'scan') return scan(rest);
  if (cmd === 'check') return check(rest);
  if (cmd === 'probe') return probeCmd(rest);
  if (cmd === 'idor') return idorCmd(rest);
  if (cmd === 'audit') return auditCmd(rest);
  if (cmd === 'rules') {
    for (const r of defaultRules()) {
      console.log(`${r.id.padEnd(28)} ${r.severity.padEnd(6)} ${r.owasp.id2025.padEnd(9)} ${[...r.langs].join(',').padEnd(22)} ${r.message}`);
    }
    return 0;
  }
  throw new UsageError(`unknown command: ${cmd}\n\n${USAGE}`);
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (e) => {
    console.error(`error: ${e.message}`);
    process.exitCode = 2;
  },
);
