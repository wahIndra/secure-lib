// Supply-chain gate (OWASP A03).
//
// 1. What we ship must have no third-party code: the npm package has no `dependencies`, and the
//    Maven artifacts' compile/runtime SBOM contains only io.github.wahindra components.
// 2. What we ship must have no known vulnerabilities (OSV), which follows from 1, and is checked
//    anyway so the gate keeps working if a dependency is ever added.
// 3. Build and test dependencies (JUnit, Spring Boot for the starter's tests) are reported, not
//    gated: they never reach users, and the starter's Spring Boot is the application's own.
//
// Usage: node .github/scripts/check-dependencies.mjs <shipped.cdx.json> <osv-shipped.json> [<osv-all.json>]
import fs from 'node:fs';

const [shippedBom, osvShipped, osvAll] = process.argv.slice(2);
if (!shippedBom || !osvShipped) {
  console.error('usage: check-dependencies.mjs <shipped.cdx.json> <osv-shipped.json> [<osv-all.json>]');
  process.exit(2);
}

let failed = false;
const fail = (msg) => {
  console.log(`::error title=Supply chain::${msg}`);
  failed = true;
};

const pkg = JSON.parse(fs.readFileSync(new URL('../../js/package.json', import.meta.url), 'utf8'));
for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']) {
  const deps = pkg[field];
  const names = Array.isArray(deps) ? deps : Object.keys(deps ?? {});
  if (names.length) fail(`js/package.json ${field} must stay empty (zero runtime dependencies), found: ${names.join(', ')}`);
}

const bom = JSON.parse(fs.readFileSync(shippedBom, 'utf8'));
const thirdParty = (bom.components ?? []).filter((c) => c.group !== 'io.github.wahindra').map((c) => c.purl ?? `${c.group}:${c.name}`);
if (thirdParty.length) {
  const shown = thirdParty.slice(0, 10).join(', ');
  fail(`Maven artifacts pull in ${thirdParty.length} third-party runtime component(s): ${shown}${thirdParty.length > 10 ? ', ...' : ''}`);
}
console.log(`shipped: npm package with 0 dependencies; Maven ${(bom.components ?? []).length} component(s), ${thirdParty.length} third-party`);

/** [{ id, pkg, version, severity }] from osv-scanner --format json (no file when there were no findings). */
function findings(file) {
  if (!file || !fs.existsSync(file) || !fs.statSync(file).size) return [];
  const out = [];
  for (const result of JSON.parse(fs.readFileSync(file, 'utf8')).results ?? []) {
    for (const p of result.packages ?? []) {
      for (const g of p.groups ?? []) {
        out.push({ id: g.ids?.[0] ?? '?', pkg: p.package.name, version: p.package.version, severity: g.max_severity || '?' });
      }
    }
  }
  return out;
}

for (const f of findings(osvShipped)) fail(`${f.id} (CVSS ${f.severity}) in shipped ${f.pkg}@${f.version}`);

const devOnly = findings(osvAll);
if (devOnly.length) {
  console.log(`::notice title=Build and test dependencies::${devOnly.length} advisory group(s) in build/test-only dependencies (not shipped); see the job log`);
  for (const f of devOnly) console.log(`  dev/test only: ${f.id} (CVSS ${f.severity}) ${f.pkg}@${f.version}`);
} else if (osvAll) {
  console.log('build and test dependencies: no known vulnerabilities');
}

console.log(failed ? 'supply-chain gate: FAILED' : 'supply-chain gate: passed');
process.exit(failed ? 1 : 0);
