// Turns failed Surefire tests into GitHub annotations, so a failure is readable from the run
// summary (and the public checks API) without opening the full log.
// Usage: node .github/scripts/report-test-failures.mjs <directory>
import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2] ?? '.';
const reports = [];
const walk = (dir) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory() && e.name !== 'node_modules') walk(p);
    else if (/^TEST-.*\.xml$/.test(e.name) && p.includes('surefire-reports')) reports.push(p);
  }
};
walk(root);

const unescape = (s) => s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
// Annotation messages are single-line; '%' and newlines must be encoded for workflow commands.
const clean = (s) => unescape(s).replace(/%/g, '%25').replace(/\r?\n/g, '%0A').slice(0, 900);

let count = 0;
for (const file of reports) {
  const xml = fs.readFileSync(file, 'utf8');
  const re = /<testcase\b[^>]*\bname="([^"]*)"[^>]*\bclassname="([^"]*)"[^>]*>([\s\S]*?)<\/testcase>/g;
  let m;
  while ((m = re.exec(xml)) && count < 20) {
    const problem = m[3].match(/<(failure|error)\b([^>]*)>([\s\S]*?)<\/\1>/);
    if (!problem) continue;
    const message = (problem[2].match(/\bmessage="([^"]*)"/) ?? [])[1] ?? '';
    const firstFrames = unescape(problem[3]).split('\n').slice(0, 4).join(' | ');
    console.log(`::error title=${m[2].split('.').pop()}.${unescape(m[1])}::${clean(message)} ${clean(firstFrames)}`);
    count++;
  }
}
console.log(`${count} failed test(s) reported from ${reports.length} report file(s)`);
