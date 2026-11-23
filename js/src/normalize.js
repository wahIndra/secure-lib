/**
 * Undoes the encodings attackers stack to slip past filters: repeated URL encoding,
 * IIS %uXXXX, overlong UTF-8, HTML entities, full-width Unicode and odd whitespace.
 * Mirrors io.github.wahindra.secure.detect.InputNormalizer.
 */

const MAX_DECODE_PASSES = 3;
export const MAX_INSPECTED_LENGTH = 64 * 1024;

const NAMED = {
  lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', colon: ':', semi: ';', tab: '\t',
  newline: '\n', lpar: '(', rpar: ')', sol: '/', bsol: '\\', period: '.', nbsp: ' ',
};

const utf8 = new TextDecoder('utf-8');

function replaceOverlongUtf8(s) {
  if (!s.includes('%')) return s;
  return s
    .replace(/%c0%ae|%e0%80%ae|%c0%2e/gi, '.')
    .replace(/%c0%af|%e0%80%af|%c0%2f/gi, '/')
    .replace(/%c1%9c|%c1%1c|%c0%5c/gi, '\\');
}

const isHex = (s, from, len) => from + len <= s.length && /^[0-9a-fA-F]+$/.test(s.slice(from, from + len));

/** Lenient percent decoding: malformed escapes are left as-is, '+' is not treated as space. */
export function percentDecode(s) {
  if (!s.includes('%')) return s;
  let out = '';
  let bytes = [];
  const flush = () => {
    if (bytes.length) {
      out += utf8.decode(Uint8Array.from(bytes));
      bytes = [];
    }
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '%' && (s[i + 1] === 'u' || s[i + 1] === 'U') && isHex(s, i + 2, 4)) {
      flush();
      out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16));
      i += 6;
    } else if (c === '%' && isHex(s, i + 1, 2)) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 3;
    } else {
      flush();
      out += c;
      i++;
    }
  }
  flush();
  return out;
}

function decodeHtmlEntities(s) {
  if (!s.includes('&')) return s;
  return s
    .replace(/&#(x[0-9a-fA-F]{1,6}|[0-9]{1,7});?/g, (m, num) => {
      const cp = num[0] === 'x' || num[0] === 'X' ? parseInt(num.slice(1), 16) : parseInt(num, 10);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    })
    .replace(/&([a-zA-Z]{2,8});/g, (m, name) => NAMED[name.toLowerCase()] ?? m);
}

/** Decoded, NFKC-normalized, case preserved. Use when the exact value still matters (file names). */
export function decode(input) {
  if (input == null) return '';
  let s = String(input);
  for (let i = 0; i < MAX_DECODE_PASSES; i++) {
    const next = decodeHtmlEntities(percentDecode(replaceOverlongUtf8(s)));
    if (next === s) break;
    s = next;
  }
  // Pure ASCII is already NFKC-normalized.
  return /^[\x00-\x7f]*$/.test(s) ? s : s.normalize('NFKC');
}

// \0 is kept: the path detector reports null-byte injection.
const SPACE_RUN = /[\s\p{Z}\u0001-\u001f\u007f-\u009f]+/gu;

/** decode(), lower-cased, with every whitespace or control run collapsed to one space. */
export function normalize(input) {
  return decode(input).toLowerCase().replace(SPACE_RUN, ' ').trim();
}

/** Pre-computed views of one raw input, shared by all detectors so decoding runs once. */
export class NormalizedInput {
  constructor(raw) {
    this.raw = raw == null ? '' : String(raw);
    const limited = this.raw.length > MAX_INSPECTED_LENGTH ? this.raw.slice(0, MAX_INSPECTED_LENGTH) : this.raw;
    /** Fully decoded, lower-cased, whitespace collapsed. Comments intact. */
    this.decoded = normalize(limited);
    this._stripped = undefined;
    this._compact = undefined;
  }

  /** decoded with SQL comments and '+' turned into spaces. */
  get stripped() {
    if (this._stripped === undefined) {
      let s = this.decoded;
      let changed = false;
      if (s.includes('/*') || s.includes('*/')) {
        // MySQL executes the body of /*!50000 ... */, so only the markers are removed.
        s = s.replace(/\/\*!\d*/g, ' ').replace(/\/\*[\s\S]*?(\*\/|$)/g, ' ').replace(/\*\//g, ' ');
        changed = true;
      }
      if (s.includes('+')) {
        s = s.replace(/\+/g, ' ');
        changed = true;
      }
      this._stripped = changed ? s.replace(/ {2,}/g, ' ') : s;
    }
    return this._stripped;
  }

  /** stripped with all whitespace removed. Catches "pg_sl eep(" style splitting. */
  get compact() {
    if (this._compact === undefined) {
      this._compact = this.stripped.replace(/[ \0]/g, '');
    }
    return this._compact;
  }

  view(name) {
    return name === 'stripped' ? this.stripped : name === 'compact' ? this.compact : this.decoded;
  }
}
