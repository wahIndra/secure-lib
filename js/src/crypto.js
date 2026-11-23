import crypto from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2 = promisify(crypto.pbkdf2);

export const DEFAULT_ITERATIONS = 600_000;
const PREFIX = 'pbkdf2_sha256';
const MAX_ITERATIONS = 10_000_000;
const MAX_PASSWORD_CHARS = 1024;

const b64 = (buf) => buf.toString('base64').replace(/=+$/, '');

/**
 * PBKDF2-HMAC-SHA256 password hashing, same stored format as the Java PasswordHasher so
 * either side can verify: `pbkdf2_sha256$600000$<salt b64>$<hash b64>`. 600,000 iterations
 * follows the OWASP Password Storage Cheat Sheet. Async, so it does not block the event loop.
 */
export class PasswordHasher {
  constructor(iterations = DEFAULT_ITERATIONS) {
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
      throw new RangeError('iterations out of range');
    }
    this.iterations = iterations;
  }

  async hash(password) {
    if (typeof password !== 'string' || !password.length || password.length > MAX_PASSWORD_CHARS) {
      throw new RangeError('password length out of range');
    }
    const salt = crypto.randomBytes(16);
    const dk = await pbkdf2(password, salt, this.iterations, 32, 'sha256');
    return `${PREFIX}$${this.iterations}$${b64(salt)}$${b64(dk)}`;
  }

  /** Constant-time check. Resolves false for malformed stored values instead of throwing. */
  async verify(password, stored) {
    if (typeof password !== 'string' || password.length > MAX_PASSWORD_CHARS || typeof stored !== 'string') return false;
    const parts = stored.split('$');
    if (parts.length !== 4 || parts[0] !== PREFIX) return false;
    const iter = Number(parts[1]);
    if (!Number.isInteger(iter) || iter < 1 || iter > MAX_ITERATIONS) return false;
    const salt = Buffer.from(parts[2], 'base64');
    const expected = Buffer.from(parts[3], 'base64');
    if (expected.length < 16 || expected.length > 64) return false;
    const actual = await pbkdf2(password, salt, iter, expected.length, 'sha256');
    return crypto.timingSafeEqual(expected, actual);
  }

  /** True when the stored hash uses fewer iterations than this hasher; re-hash after login. */
  needsRehash(stored) {
    const parts = typeof stored === 'string' ? stored.split('$') : [];
    if (parts.length !== 4 || parts[0] !== PREFIX) return true;
    return !(Number(parts[1]) >= this.iterations);
  }
}

/** URL-safe random token; 32 bytes gives 256 bits of entropy. */
export function randomToken(bytes = 32) {
  if (bytes < 16) throw new RangeError('use at least 16 bytes (128 bits)');
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Constant-time string comparison for tokens, signatures and API keys. */
export function constantTimeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  // Length is not secret for tokens of a fixed format; content comparison is constant-time.
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** SHA-256 of a high-entropy token for storage (reset tokens, API keys). Not for passwords. */
export function sha256Token(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('base64url');
}

/** HMAC-SHA256 signing (signed cookies/URLs, webhook verification). Output is base64url. */
export class HmacSigner {
  constructor(secretKey) {
    const key = typeof secretKey === 'string' ? Buffer.from(secretKey, 'utf8') : secretKey;
    if (!key || key.length < 32) throw new RangeError('HMAC key must be at least 32 bytes');
    this.key = Buffer.from(key);
  }

  sign(data) {
    return crypto.createHmac('sha256', this.key).update(data).digest('base64url');
  }

  verify(data, signature) {
    return data != null && typeof signature === 'string' && constantTimeEquals(this.sign(data), signature);
  }

  /** Hex signature, e.g. `X-Hub-Signature-256: sha256=<hex>`. Pass the raw request body. */
  verifyHex(payload, hexSignature) {
    if (payload == null || typeof hexSignature !== 'string') return false;
    const sig = hexSignature.startsWith('sha256=') ? hexSignature.slice(7) : hexSignature;
    const mac = crypto.createHmac('sha256', this.key).update(payload).digest('hex');
    return constantTimeEquals(mac, sig.toLowerCase());
  }
}

const COMMON = new Set([
  '123456', '123456789', '12345678', 'password', 'qwerty123', 'qwerty', '1234567890', '111111',
  '1234567', 'password1', '123123', 'abc123', 'iloveyou', 'admin', 'admin123', 'welcome',
  'welcome1', 'letmein', 'monkey', 'dragon', 'sunshine', 'princess', 'football', 'baseball',
  'passw0rd', 'p@ssw0rd', 'p@ssword', 'changeme', 'secret', 'trustno1', 'qwertyuiop',
  '1q2w3e4r', 'zaq12wsx', 'password123', 'administrator', 'root', 'toor', 'master', 'superman',
  '000000', '654321', '666666', '888888', '121212', 'asdfghjkl', 'michael', 'shadow', 'starwars',
]);

/** NIST SP 800-63B style rules. Returns a list of messages; empty means acceptable. */
export function validatePassword(password, { username, minLength = 12, maxLength = 128 } = {}) {
  const errors = [];
  if (typeof password !== 'string' || password.length < minLength) {
    return [`Password must be at least ${minLength} characters.`];
  }
  if (password.length > maxLength) errors.push(`Password must be at most ${maxLength} characters.`);
  const p = password.toLowerCase();
  if (COMMON.has(p) || COMMON.has(p.replace(/[0-9!@#$%^&*.]+$/, ''))) errors.push('Password is too common.');
  if (username && username.length >= 3 && p.includes(username.toLowerCase())) errors.push('Password must not contain the user name.');
  const chars = [...p];
  const same = chars.every((c) => c === chars[0]);
  const ascending = chars.every((c, i) => i === 0 || c.charCodeAt(0) === chars[i - 1].charCodeAt(0) + 1);
  if (same || ascending) errors.push('Password must not be a repeated or sequential pattern.');
  return errors;
}

/**
 * In-memory brute-force / credential-stuffing protection. Key by account and, separately,
 * by client IP. For multiple instances, back it with a shared store using the same rules.
 *
 * Capacity: at most `maxTrackedKeys` keys. Only entries whose window and lockout have both
 * expired are removed; live counters are never evicted (that would let an attacker reset a
 * victim's counter by flooding the limiter). When full of live entries it fails closed: keys it
 * is not already tracking are reported as locked until expired entries free space (at most one
 * window). Size `maxTrackedKeys` for your traffic and alert on `saturated`.
 */
export class LoginAttemptLimiter {
  constructor({ maxFailures = 5, windowMs = 15 * 60_000, lockoutMs = 15 * 60_000, maxTrackedKeys = 100_000, now = Date.now } = {}) {
    Object.assign(this, { maxFailures, windowMs, lockoutMs, maxTrackedKeys, now });
    this.entries = new Map();
  }

  isLocked(key) {
    const now = this.now();
    const e = this.entries.get(key);
    return e ? e.lockedUntil > now : !this.#hasRoom(now);
  }

  /** Remaining lock in ms (0 if not locked). Use for the Retry-After header. */
  retryAfterMs(key) {
    const now = this.now();
    const e = this.entries.get(key);
    if (!e) return this.#hasRoom(now) ? 0 : this.windowMs;
    return Math.max(0, e.lockedUntil - now);
  }

  recordFailure(key) {
    const now = this.now();
    let e = this.entries.get(key);
    if (!e) {
      // Saturated: the key is already reported as locked by isLocked(), so the caller should not
      // have verified a password for it. Nothing to record.
      if (!this.#hasRoom(now)) return;
      e = { failures: 0, windowStart: now, lockedUntil: 0 };
      this.entries.set(key, e);
    }
    if (now - e.windowStart > this.windowMs) {
      e.windowStart = now;
      e.failures = 0;
    }
    e.failures++;
    if (e.failures >= this.maxFailures) {
      e.lockedUntil = now + this.lockoutMs;
      e.failures = 0;
      e.windowStart = now;
    }
  }

  recordSuccess(key) {
    this.entries.delete(key);
  }

  /** True while the limiter is full of live entries and fails closed for new keys. */
  get saturated() {
    return !this.#hasRoom(this.now());
  }

  /** Number of keys currently tracked (for monitoring). */
  get trackedKeys() {
    return this.entries.size;
  }

  /**
   * Whether a new key can be tracked. When full, removes expired entries; the scan runs at most
   * once per second so a flood of new keys cannot turn every request into an O(n) scan.
   */
  #hasRoom(now) {
    if (this.entries.size < this.maxTrackedKeys) return true;
    if (now - this.#lastMaintenance >= MAINTENANCE_INTERVAL_MS) {
      this.#lastMaintenance = now;
      for (const [k, e] of this.entries) {
        if (e.lockedUntil <= now && now - e.windowStart > this.windowMs) this.entries.delete(k);
      }
    }
    return this.entries.size < this.maxTrackedKeys;
  }

  #lastMaintenance = -Infinity;
}

const MAINTENANCE_INTERVAL_MS = 1000;
