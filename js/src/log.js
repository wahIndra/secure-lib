import crypto from 'node:crypto';

export const DEFAULT_MAX_LENGTH = 1000;

const KEY_VALUE_SECRET =
  /("?(?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|client_secret|authorization|cookie|session(?:id)?|jsessionid|private[_-]?key)"?\s*[=:]\s*"?)(?!(?:bearer|basic)\s)([^\s"&,;]+)/gi;
const BEARER = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g;

export function maskSecrets(value) {
  if (value == null) return value;
  return String(value).replace(KEY_VALUE_SECRET, '$1****').replace(BEARER, '$1 ****').replace(JWT, 'eyJ****');
}

/**
 * Makes untrusted values safe to log: neutralizes CR/LF (log forging), escapes control
 * characters, masks secrets and truncates. Apply to every user-controlled value.
 */
export function sanitizeForLog(value, maxLength = DEFAULT_MAX_LENGTH) {
  if (value == null) return 'null';
  let v = String(value);
  if (v.length > maxLength * 4) v = v.slice(0, maxLength * 4);
  v = maskSecrets(v);
  let out = '';
  for (const c of v) {
    if (out.length >= maxLength) break;
    if (c === '\r') out += '\\r';
    else if (c === '\n') out += '\\n';
    else if (c === '\t') out += '\\t';
    else if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(c)) out += `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
    else out += c;
  }
  if (out.length >= maxLength && v.length > maxLength) out += '...[truncated]';
  return out;
}

export const PUBLIC_ERROR_MESSAGE = 'An unexpected error occurred.';

/**
 * Mishandling of Exceptional Conditions: log full detail under an incident id, return only a
 * generic message and that id to the client.
 *
 * @returns {string} the incident id
 */
export function logError(logger, error, context = '') {
  const id = crypto.randomUUID();
  const detail = error instanceof Error ? error.stack ?? error.message : String(error);
  (logger.error ?? logger.log).call(logger, `incident=${id} ${sanitizeForLog(context)} ${sanitizeForLog(detail, 8000)}`);
  return id;
}

export function publicErrorBody(incidentId) {
  return { error: PUBLIC_ERROR_MESSAGE, incidentId: String(incidentId).replace(/[^A-Za-z0-9-]/g, '') };
}
