// Fails when the Java and JavaScript scanners disagree on the shared fixtures.
// Usage: node .github/scripts/compare-scanners.mjs java.json js.json
import fs from 'node:fs';

const [javaReport, jsReport] = process.argv.slice(2);
if (!javaReport || !jsReport) {
  console.error('usage: compare-scanners.mjs <java.json> <js.json>');
  process.exit(2);
}

const keys = (file) => JSON.parse(fs.readFileSync(file, 'utf8')).findings
  .map((f) => `${f.file.split('\\').join('/')}:${f.line}:${f.rule}`)
  .sort();

const java = keys(javaReport);
const js = keys(jsReport);
const onlyJava = java.filter((k) => !js.includes(k));
const onlyJs = js.filter((k) => !java.includes(k));

if (onlyJava.length || onlyJs.length) {
  console.error('Scanners disagree.');
  if (onlyJava.length) console.error(`only Java:\n  ${onlyJava.join('\n  ')}`);
  if (onlyJs.length) console.error(`only JavaScript:\n  ${onlyJs.join('\n  ')}`);
  process.exit(1);
}
console.log(`${java.length} findings identical in both scanners`);
