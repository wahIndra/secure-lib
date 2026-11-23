/**
 * Contextual output encoders. Pick the one matching where the value lands; HTML-encoding a
 * value placed inside a script block does not make it safe. Prefer your template engine's
 * auto-escaping (React, Vue, Handlebars {{ }}), and use these where you build strings by hand.
 */

const HTML = { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#x27;', '/': '&#x2F;', '`': '&#x60;' };
const isAlnumAscii = (c) => /[A-Za-z0-9]/.test(c);

/** Text between tags: `<p>VALUE</p>`. */
export function forHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[<>&"'/`]|[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, (c) => HTML[c] ?? ' ');
}

/** Quoted attribute value: `<input value="VALUE">`. Encodes every non-alphanumeric ASCII char. */
export function forHtmlAttribute(s) {
  if (s == null) return '';
  return [...String(s)].map((c) => (c.charCodeAt(0) < 0x80 && !isAlnumAscii(c) ? `&#x${c.charCodeAt(0).toString(16)};` : c)).join('');
}

/** Inside a quoted JavaScript string: `var x = 'VALUE';`. Also safe inside a script block. */
export function forJavaScript(s) {
  if (s == null) return '';
  return [...String(s)]
    .map((c) => {
      const code = c.charCodeAt(0);
      if (code < 0x80 && !isAlnumAscii(c) && !' ,._'.includes(c)) return `\\x${code.toString(16).padStart(2, '0')}`;
      if (c === '\u2028' || c === '\u2029') return `\\u${code.toString(16)}`;
      return c;
    })
    .join('');
}

/** A single query-string value or path segment. */
export function forUrlComponent(s) {
  if (s == null) return '';
  return encodeURIComponent(String(s)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Quoted CSS string value. */
export function forCssString(s) {
  if (s == null) return '';
  return [...String(s)].map((c) => (c.charCodeAt(0) < 0x80 && !isAlnumAscii(c) ? `\\${c.charCodeAt(0).toString(16)} ` : c)).join('');
}

/** Returns the URL only if it is http(s), mailto or relative; otherwise '#'. */
export function safeUrl(url) {
  if (url == null) return '#';
  const t = String(url).trim();
  let scheme = '';
  for (const c of t) {
    if (c === ':') return ['http', 'https', 'mailto'].includes(scheme.toLowerCase()) ? t : '#';
    if (c === '/' || c === '?' || c === '#') break;
    if (!/[\s\u0000-\u001f\u007f-\u009f]/.test(c)) scheme += c;
  }
  return t;
}
