/**
 * Signature detectors. Rule ids, views and severities match the Java implementation so
 * findings from both stacks can be correlated. Both suites run /test-vectors.
 *
 * These are a second line of defence for monitoring and blocking scanners. The fixes are
 * parameterized queries, output encoding, never using a shell, and safe path resolution.
 */
import { NormalizedInput } from './normalize.js';
import { OwaspCategory, SecurityViolationError } from './owasp.js';

export const Severity = Object.freeze({ LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH' });
const SCORE = { LOW: 1, MEDIUM: 3, HIGH: 10 };

/** One HIGH finding, or two MEDIUM findings, marks input as malicious. */
export const MALICIOUS_SCORE = 6;

/**
 * `required` is a literal prefilter: for every group, at least one of its strings must occur in
 * the view before the regex runs. A substring scan is far cheaper than a regex tried at every
 * position. Only list text the regex cannot match without.
 */
const rule = (id, category, severity, view, regex, description, ...required) => ({
  id,
  category,
  severity,
  view,
  pattern: regex instanceof RegExp ? regex : new RegExp(regex, 's'),
  description,
  required,
});

const passesPrefilter = (text, required) => required.every((group) => group.some((literal) => text.includes(literal)));

export function result(findings) {
  const score = findings.reduce((s, f) => s + SCORE[f.severity], 0);
  return { findings, score, malicious: score >= MALICIOUS_SCORE, suspicious: findings.length > 0 };
}

export const CLEAN = Object.freeze(result([]));

export class RuleBasedDetector {
  constructor(rules) {
    this.rules = Object.freeze([...rules]);
  }

  /** @param {string|NormalizedInput} input */
  inspect(input) {
    if (input == null || input === '') return CLEAN;
    const n = input instanceof NormalizedInput ? input : new NormalizedInput(input);
    const findings = [];
    for (const r of this.rules) {
      const text = n.view(r.view);
      if (passesPrefilter(text, r.required) && r.pattern.test(text)) {
        findings.push({ ruleId: r.id, category: r.category, severity: r.severity, description: r.description });
      }
    }
    return findings.length ? result(findings) : CLEAN;
  }

  isMalicious(input) {
    return this.inspect(input).malicious;
  }

  /** Throws SecurityViolationError when the input is malicious. */
  assertSafe(input) {
    const r = this.inspect(input);
    if (r.malicious) {
      throw new SecurityViolationError(r.findings[0].category, `attack pattern detected: ${r.findings.map((f) => f.ruleId).join(', ')}`);
    }
  }
}

// ---------------------------------------------------------------- SQL injection

const INJ = OwaspCategory.INJECTION;
// Quoted literals are length-bounded so a long unterminated quote cannot be rescanned from every OR/AND.
const LIT = `(?:\\d+(?:\\.\\d+)?|'[^']{0,100}'|"[^"]{0,100}"|true|false|null)`;
const sql = (id, sev, view, re, d, ...required) => rule(id, INJ, sev, view, re, d, ...required);

export const sqlInjectionRules = [
  // Time-based blind
  sql('SQLI_PG_SLEEP', 'HIGH', 'stripped', /\bpg_sleep(?:_for|_until)?\s*\(/s, 'PostgreSQL pg_sleep time delay', ['pg_sleep']),
  sql('SQLI_PG_SLEEP_SPLIT', 'HIGH', 'compact', /pg_?sleep(?:_for|_until)?\(/s, 'pg_sleep split by spaces or comments', ['sleep']),
  sql('SQLI_TIME_DELAY', 'HIGH', 'stripped',
    /\bsleep\s*\(\s*\d|\bbenchmark\s*\(\s*\d|\bwaitfor\s+(?:delay|time)\s+'|\bdbms_pipe\s*\.\s*receive_message|\bdbms_lock\s*\.\s*sleep|\brandomblob\s*\(\s*\d{6,}/s,
    'Time delay function (MySQL/MSSQL/Oracle/SQLite)', ['sleep', 'benchmark', 'waitfor', 'dbms_', 'randomblob']),

  // Boolean-based blind
  sql('SQLI_BOOLEAN_TAUTOLOGY', 'HIGH', 'stripped',
    `(?:^|[\\s'")(])(?:or|and|xor|\\|\\||&&)\\s*\\(*\\s*${LIT}\\s*\\)*\\s*(?:=|<>|!=|<=>|<=|>=|<|>|like\\b|is\\b)\\s*\\(*\\s*(?:${LIT}|'[^']{0,100}$|not\\s+null)`,
    'Boolean condition such as OR 1=1 / AND 1=2', ['or', 'and', 'xor', '||', '&&'], ['=', '<', '>', 'like', 'is']),
  sql('SQLI_BOOLEAN_SUBQUERY', 'HIGH', 'stripped',
    /(?:=|<>|!=|<|>|\bin\b|\bis\b|\bexists\b|\bor\b|\band\b|\bnot\b)\s*\(\s*select\b/s,
    'Comparison against a subquery (boolean/blind extraction)', ['select']),
  sql('SQLI_CASE_WHEN', 'MEDIUM', 'stripped', /\bcase\s+when\b.{1,200}?\bthen\b/s, 'CASE WHEN conditional', ['case'], ['then']),

  // Error-based
  sql('SQLI_CAST_ERROR', 'HIGH', 'stripped',
    /\bcast\s*\(\s*\(?\s*(?:select\b|version\s*\(|current_(?:user|database|setting|schema)\b|user\b|session_user\b|database\s*\(|chr\s*\(|[a-z_]+\s*\|\|)/s,
    'CAST of sensitive value to force a type error', ['cast']),
  sql('SQLI_VERSION_CAST', 'HIGH', 'compact',
    /version\(\)::|cast\(\(?(?:select)?version\(\)|@@version|\bsqlite_version\(/s, 'version() cast or DB version disclosure', ['version']),
  sql('SQLI_VERSION_CALL', 'MEDIUM', 'stripped', /\bversion\s*\(\s*\)/s, 'version() call', ['version']),
  sql('SQLI_TYPE_CAST', 'MEDIUM', 'stripped', /\)\s*::\s*(?:int|integer|numeric|bigint|smallint|text)\b/s, 'PostgreSQL :: cast after expression', ['::']),
  sql('SQLI_ERROR_FUNCTION', 'HIGH', 'stripped',
    /\b(?:extractvalue|updatexml|exp\s*\(\s*~|convert\s*\(\s*int\s*,|ctxsys\s*\.\s*drithsx)/s, 'Error-based extraction function', ['extractvalue', 'updatexml', 'exp', 'convert', 'drithsx']),
  sql('SQLI_RAISE_EXCEPTION', 'HIGH', 'stripped',
    /\braise\s+(?:exception|notice|warning|info|log|debug)\s+(?:'|\$|using\b)/s, 'PL/pgSQL RAISE EXCEPTION used to leak data', ['raise']),
  sql('SQLI_RAISE_EXCEPTION_SPLIT', 'HIGH', 'compact', /raise(?:exception|notice|warning)(?:'|\$\$|using)/s, 'RAISE EXCEPTION split by spaces or comments', ['raise']),
  sql('SQLI_RAISE_KEYWORD', 'MEDIUM', 'stripped', /\braise\s+exception\b/s, 'RAISE EXCEPTION keyword', ['raise']),

  // Dynamic / procedural execution
  sql('SQLI_EXECUTE_DYNAMIC', 'HIGH', 'stripped',
    /\bexec(?:ute)?\s*(?:immediate\s+)?(?:'|\$[a-z_0-9]*\$|format\s*\(|\(\s*['@]|@|sp_|xp_|master\s*\.)/s, 'EXECUTE of a dynamic SQL string', ['exec']),
  sql('SQLI_EXECUTE_DYNAMIC_SPLIT', 'HIGH', 'compact', /execute(?:immediate)?(?:'|format\(|\$\$)/s, 'EXECUTE split by spaces or comments', ['execute']),
  sql('SQLI_PG_DO_BLOCK', 'HIGH', 'stripped', /\bdo\s*\$[a-z_0-9]*\$/s, 'PostgreSQL anonymous DO $$ block', ['do'], ['$']),
  sql('SQLI_MSSQL_PROC', 'HIGH', 'stripped',
    /\b(?:xp_cmdshell|sp_executesql|sp_oacreate|sp_configure|xp_dirtree|xp_regread)\b/s, 'Dangerous MSSQL procedure', ['xp_', 'sp_']),

  // Structure
  sql('SQLI_UNION_SELECT', 'HIGH', 'stripped', /\bunion\b(?:\s+(?:all|distinct))?\s*\(*\s*select\b/s, 'UNION SELECT', ['union'], ['select']),
  sql('SQLI_STACKED_QUERY', 'HIGH', 'stripped',
    /;\s*(?:select\b.{0,200}?\bfrom\b|select\s+(?:pg_sleep|version|current_|user\b|\d|null|\*|case\b)|insert\s+into\b|update\s+[a-z_."]+\s+set\b|delete\s+from\b|truncate\s+(?:table\s+)?[a-z_]|drop\s+(?:table|database|schema|view|function|user|role|index)\b|alter\s+(?:table|user|role|system|database)\b|create\s+(?:table|function|user|role|or\s+replace)\b|grant\s+[a-z]|revoke\s+[a-z]|exec(?:ute)?\s|declare\s+[@a-z]|do\s*\$|copy\s+[a-z(]|shutdown\b)/s,
    'Stacked (piggy-backed) statement', [';']),
  sql('SQLI_QUOTE_COMMENT_END', 'HIGH', 'decoded',
    // "/*" and ";--" after a quote always run to the end of input, so they need no "$" (keeps this linear).
    /['")]\s*(?:\/\*|;\s*--|(?:--[\s-]*|#\s*)$)/s, "Quote break-out followed by trailing comment (admin'--)", ["'", '"', ')'], ['--', '#', '/*', ';']),
  sql('SQLI_QUOTE_COMMENT', 'MEDIUM', 'decoded', /['")]\s*(?:--|#|\/\*)/s, 'Quote followed by comment', ["'", '"', ')'], ['--', '#', '/*']),
  sql('SQLI_INLINE_COMMENT', 'MEDIUM', 'decoded', /[a-z0-9_]\/\*.{0,200}?\*\/[a-z0-9_(]|\/\*!\d*/s, 'Inline comment used as keyword separator', ['/*']),
  sql('SQLI_ORDER_BY_PROBE', 'HIGH', 'stripped', /\border\s+by\s+\d+\s*(?:--|#)/s, 'Column-count probe (ORDER BY n--)', ['order']),
  sql('SQLI_ORDER_BY_NUMBER', 'MEDIUM', 'stripped', /\border\s+by\s+\d+\s*$|\bgroup\s+by\b.{0,100}?\bhaving\b/s, 'ORDER BY n / GROUP BY ... HAVING', ['order', 'having']),
  sql('SQLI_CHAR_CONCAT', 'MEDIUM', 'stripped', /\bchr\s*\(\s*\d+\s*\)\s*\|\||\bchar\s*\(\s*\d+(?:\s*,\s*\d+){2,}/s, 'CHR()/CHAR() string building', ['chr', 'char']),

  // Data and system access
  sql('SQLI_SYSTEM_CATALOG', 'MEDIUM', 'stripped',
    /\binformation_schema\b|\bpg_catalog\b|\bpg_(?:shadow|authid|user|roles|tables|namespace|proc|stat_activity)\b|\bsys\s*\.\s*(?:objects|tables|columns|databases)\b|\bsysobjects\b|\bmysql\s*\.\s*user\b|\bsqlite_master\b|\ball_tables\b/s,
    'System catalog access', ['information_schema', 'pg_', 'sys', 'mysql', 'sqlite_master', 'all_tables']),
  sql('SQLI_FILE_OR_COMMAND', 'HIGH', 'stripped',
    /\bcopy\b[^;]{0,200}?\b(?:from|to)\s+program\b|\bpg_(?:read_file|read_binary_file|ls_dir|stat_file)\s*\(|\blo_(?:import|export)\s*\(|\bload_file\s*\(|\binto\s+(?:out|dump)file\b|\bdblink(?:_exec|_connect)?\s*\(|\butl_(?:http|inaddr|file)\b/s,
    'File read/write or OS command through the database', ['program', 'pg_', 'lo_', 'load_file', 'outfile', 'dumpfile', 'dblink', 'utl_']),
  sql('SQLI_CURRENT_CONTEXT', 'LOW', 'stripped',
    /\b(?:current_user|session_user|current_database\s*\(|current_setting\s*\(|database\s*\(\s*\))/s, 'Database context function', ['current_', 'session_user', 'database']),
];

// ---------------------------------------------------------------- XSS

export const xssRules = [
  rule('XSS_SCRIPT_TAG', INJ, 'HIGH', 'decoded', /<\s*\/?\s*script\b/s, '<script> tag', ['script'], ['<']),
  rule('XSS_EVENT_HANDLER', INJ, 'HIGH', 'decoded', /<[a-z!/][^<>]{0,1000}?[\s/"'`]on[a-z]{3,}\s*=/s, 'Inline event handler inside a tag (onerror=, onload=)', ['<'], ['on'], ['=']),
  rule('XSS_JS_URI', INJ, 'HIGH', 'compact', /(?:javascript|vbscript|livescript):|data:text\/html|data:[a-z/+-]*;base64,/s, 'Script-capable URI scheme', ['script:', 'data:']),
  rule('XSS_DANGEROUS_TAG', INJ, 'HIGH', 'decoded',
    /<\s*(?:iframe|frame|object|embed|applet|base|meta|link|svg|math|template|form|isindex)\b/s, 'Tag that can load or run content', ['<']),
  rule('XSS_ATTRIBUTE', INJ, 'MEDIUM', 'decoded', /\b(?:srcdoc|formaction|xlink:href|style)\s*=/s, 'Attribute that can carry script', ['srcdoc', 'formaction', 'xlink:href', 'style']),
  rule('XSS_CSS_EXPRESSION', INJ, 'MEDIUM', 'compact', /expression\(|-moz-binding|behavior:url\(/s, 'Legacy CSS script execution', ['expression(', '-moz-binding', 'behavior:']),
  rule('XSS_DOM_SINK', INJ, 'MEDIUM', 'compact',
    /document\.(?:cookie|domain|write)|window\.location|\.innerhtml=|\beval\(|settimeout\(['"`]|string\.fromcharcode\(|\balert\(|\bprompt\(|\bconfirm\(/s,
    'DOM sink or classic probe call', ['document.', 'window.location', '.innerhtml', 'eval(', 'settimeout(', 'fromcharcode(', 'alert(', 'prompt(', 'confirm(']),
  rule('XSS_TEMPLATE_INJECTION', INJ, 'MEDIUM', 'compact', /\{\{[^}]{0,200}?(?:constructor|\$on|\$eval|alert|prototype)[^}]{0,200}?\}\}/s, 'Client-side template injection', ['{{'], ['constructor', '$on', '$eval', 'alert', 'prototype']),
];

// ---------------------------------------------------------------- Command / JNDI / EL injection

const COMMANDS =
  '(?:sh|bash|zsh|dash|ksh|csh|nc|ncat|netcat|socat|telnet|curl|wget|python[0-9.]*|perl|ruby|php|' +
  'powershell|pwsh|cmd(?:\\.exe)?|certutil|bitsadmin|whoami|id|uname|cat|ls|dir|ping|nslookup|' +
  'rm|chmod|chown|mkfifo|base64|env|type|net|ifconfig|ipconfig)';

export const commandInjectionRules = [
  rule('CMD_SUBSTITUTION', INJ, 'HIGH', 'decoded', /\$\([^)]{1,200}\)|\$\{ifs\}|\$ifs\$/s, 'Shell command substitution $(...) or $IFS', ['$(', '${ifs}', '$ifs$']),
  rule('CMD_BACKTICK', INJ, 'MEDIUM', 'decoded', /`[^`]{1,200}`/s, 'Backtick command substitution', ['`']),
  rule('CMD_CHAINED', INJ, 'HIGH', 'decoded',
    `(?:[;&|\`\\n]|&&|\\|\\|)\\s*${COMMANDS}(?:\\s+-{1,2}[a-z]|\\s+/|\\s+(?:https?|ftp)://|\\s*$|\\s*[;|&#]|\\s+[a-z0-9.:/-]+\\s*[|;&])`,
    'Shell separator followed by a command', [';', '&', '|', '`']),
  rule('CMD_PIPE_TO_SHELL', INJ, 'HIGH', 'decoded', /\|\s*(?:\/bin\/|\/usr\/bin\/)?(?:sh|bash|zsh|python[0-9.]*|perl|powershell|cmd)\b/s, 'Pipe into an interpreter', ['|']),
  rule('CMD_SHELL_PATH', INJ, 'HIGH', 'decoded',
    /\/bin\/(?:ba|z|da|k)?sh\b|cmd(?:\.exe)?\s+\/c\b|powershell(?:\.exe)?\s+-(?:e|enc|c|command|nop)\b/s, 'Direct interpreter invocation', ['/bin/', 'cmd', 'powershell']),
  rule('CMD_REVERSE_SHELL', INJ, 'HIGH', 'decoded', /\bnc(?:at)?\s+(?:-[a-z]*[ec]\b|.{0,200}?\s-e\s)|\/dev\/tcp\/|\bmkfifo\b/s, 'Reverse shell pattern', ['nc', '/dev/tcp/', 'mkfifo']),
  rule('JNDI_LOOKUP', INJ, 'HIGH', 'compact', /\$\{(?:jndi|\$\{|lower:|upper:|env:|sys:|::-)/s, 'JNDI/Log4Shell lookup', ['${']),
  rule('EL_INJECTION', INJ, 'HIGH', 'compact',
    /[$#]\{[^}]{0,200}(?:t\(java\.|getruntime|processbuilder|getclass\(|classloader|forname\()/s, 'Expression-language / OGNL injection', ['{'], ['java.', 'getruntime', 'processbuilder', 'getclass(', 'classloader', 'forname(']),
  rule('SSTI_PROBE', INJ, 'MEDIUM', 'compact', /\{\{[^}]{0,100}(?:__class__|__globals__|__subclasses__|config\.|self\.)/s, 'Server-side template injection', ['{{'], ['__class__', '__globals__', '__subclasses__', 'config.', 'self.']),
];

// ---------------------------------------------------------------- Path traversal

const BAC = OwaspCategory.BROKEN_ACCESS_CONTROL;

export const pathTraversalRules = [
  rule('PATH_DOT_DOT', BAC, 'HIGH', 'decoded', /(?:^|[\\/])\.{2,}(?:[\\/]|$)/s, '../ traversal segment (after decoding)', ['..']),
  rule('PATH_NULL_BYTE', BAC, 'HIGH', 'decoded', /\x00/s, 'Null byte (extension truncation)', ['\0']),
  rule('PATH_SENSITIVE_FILE', BAC, 'HIGH', 'decoded',
    /(?:^|[\\/])(?:etc[\\/](?:passwd|shadow|group|hosts|sudoers)|proc[\\/](?:self|\d+)[\\/]|windows[\\/](?:win\.ini|system32)|boot\.ini|web-inf[\\/]|meta-inf[\\/]|\.ssh[\\/]|\.aws[\\/]credentials|\.git[\\/](?:config|head)|\.env(?:$|\.))/s,
    'Well-known sensitive file', ['etc', 'proc', 'windows', 'boot.ini', 'web-inf', 'meta-inf', '.ssh', '.aws', '.git', '.env']),
  rule('PATH_WRAPPER', BAC, 'HIGH', 'compact', /^(?:file|php|zip|phar|jar|expect|glob|data|netdoc|gopher):\/\/|^php:filter/s, 'Stream wrapper / URL scheme as path', ['://', 'php:']),
  rule('PATH_ABSOLUTE', BAC, 'MEDIUM', 'decoded', /^(?:\/|\\\\|[a-z]:[\\/])/s, 'Absolute or UNC path'),
  rule('PATH_DOT_DOT_DOUBLE', BAC, 'HIGH', 'decoded', /\.\.\.\.[\\/]{1,2}|\.\.[\\/]{2}|\.\.;\//s, 'Filter evasion (....// or ..;/)', ['..']),
];

export const sqlInjectionDetector = new RuleBasedDetector(sqlInjectionRules);
export const xssDetector = new RuleBasedDetector(xssRules);
export const commandInjectionDetector = new RuleBasedDetector(commandInjectionRules);
export const pathTraversalDetector = new RuleBasedDetector(pathTraversalRules);

/** Runs several detectors over one input, normalizing it only once. */
export class InputInspector {
  constructor(detectors = [sqlInjectionDetector, xssDetector, commandInjectionDetector, pathTraversalDetector]) {
    this.detectors = Object.freeze([...detectors]);
  }

  inspect(input) {
    if (input == null || input === '') return CLEAN;
    const n = new NormalizedInput(input);
    const findings = this.detectors.flatMap((d) => d.inspect(n).findings);
    return findings.length ? result(findings) : CLEAN;
  }

  isMalicious(input) {
    return this.inspect(input).malicious;
  }
}

export const inputInspector = new InputInspector();
