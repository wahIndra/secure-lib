import { OwaspCategory, SecurityViolationError } from './owasp.js';

const violation = (msg) => new SecurityViolationError(OwaspCategory.INJECTION, msg);

/**
 * Helpers for the parts of SQL that placeholders cannot cover: identifiers (ORDER BY column,
 * table name), sort direction, IN-list size and LIKE patterns.
 *
 * @example
 * const col = SafeSql.allowlisted(req.query.sort, ['created_at', 'total']);
 * await db.query(`SELECT * FROM orders WHERE owner_id = $1 ORDER BY ${col} ${SafeSql.direction(req.query.dir)}`, [userId]);
 */
export const SafeSql = {
  allowlisted(value, allowed) {
    const v = typeof value === 'string' ? value.trim() : null;
    const hit = v && allowed.find((a) => a.toLowerCase() === v.toLowerCase());
    if (!hit) throw violation('identifier not in allowlist');
    return hit;
  },

  /** Maps a public name to a real column, e.g. { created: 'o.created_at' }. */
  mapped(value, publicToColumn) {
    const key = typeof value === 'string' ? value.trim().toLowerCase() : null;
    const column = key != null && Object.hasOwn(publicToColumn, key) ? publicToColumn[key] : undefined;
    if (!column) throw violation('identifier not in allowlist');
    return column;
  },

  /** Validates a plain identifier and wraps it in double quotes (ANSI / PostgreSQL). */
  quoteIdentifier(name) {
    if (typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name)) throw violation('invalid SQL identifier');
    return `"${name}"`;
  },

  direction(value, defaultDirection = 'ASC') {
    const v = typeof value === 'string' ? value.trim().toUpperCase() : '';
    if (v === 'ASC' || v === 'DESC') return v;
    return String(defaultDirection).toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
  },

  /** "?, ?, ?" (or "$1, $2, $3" with style 'pg' and a start index) for an IN clause. */
  placeholders(count, { style = '?', start = 1 } = {}) {
    if (!Number.isInteger(count) || count < 1 || count > 1000) throw violation('IN list size must be between 1 and 1000');
    return Array.from({ length: count }, (_, i) => (style === 'pg' ? `$${start + i}` : '?')).join(', ');
  },

  /** Escapes %, _ and \ so user text is matched literally. Use with `LIKE $1 ESCAPE '\'`. */
  escapeLike(value) {
    return value == null ? value : String(value).replace(/[\\%_]/g, '\\$&');
  },

  clamp(value, min, max, defaultValue) {
    const n = Number.parseInt(value, 10);
    return Number.isNaN(n) ? defaultValue : Math.max(min, Math.min(max, n));
  },
};

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh']);

/**
 * Validates a command and its arguments for `execFile`/`spawn` (never `exec`, which uses a
 * shell). Rejects shell interpreters, option injection (leading '-') and metacharacters.
 *
 * @example
 * const [cmd, args] = safeCommand('/usr/bin/convert', [input, output]);
 * execFile(cmd, args, { shell: false }, callback);
 */
export function safeCommand(executable, userArgs = [], constantOptions = []) {
  if (!executable) throw violation('executable is required');
  const name = executable.replace(/\\/g, '/').split('/').pop().toLowerCase();
  if (SHELLS.has(name)) throw violation('shell interpreters are not allowed as the executable');
  for (const a of userArgs) {
    if (typeof a !== 'string' || !/^[A-Za-z0-9._,:=@/\\+-]{1,1024}$/.test(a) || a.startsWith('-')) {
      throw violation('unsafe command argument');
    }
  }
  return [executable, [...constantOptions, ...userArgs]];
}
