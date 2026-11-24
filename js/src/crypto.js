import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { OwaspCategory } from './owasp.js';
import { securityEvent, SecurityEventType } from './api.js';

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
 * Bounded memory without blocking anyone: at most `maxTrackedKeys` keys are kept. Expired
 * entries are dropped first. If the limiter is still full, it evicts the entry with the fewest
 * live failures (oldest first), and active lockouts only after every unlocked entry. Unknown keys
 * are never refused, so a flood of throwaway usernames cannot lock out real users.
 *
 * The cost of an attack keeps this safe: to evict a victim holding k failures, an attacker must
 * first fill the whole table with entries holding at least k failures each, i.e. at least
 * k * maxTrackedKeys failed attempts to win back k guesses. That is at most one extra guess per
 * maxTrackedKeys (default 100,000) attacker requests. Put a per-IP limiter in front so a single
 * source cannot generate that volume at all.
 *
 * Use separate instances for accounts and for client IPs, so a flood of one kind of key cannot
 * push the other kind out.
 *
 * Why not refuse new keys when full instead? Then a flood of throwaway usernames would lock out
 * every account the limiter is not already tracking: a cheap, total login outage. Bounded eviction
 * costs an attacker far more than it gains, while refusal costs them almost nothing.
 */
export class LoginAttemptLimiter {
  #entries = new Map();
  /** #levels[n]: entries at that level (failures while unlocked, maxFailures once locked), oldest first. */
  #levels;
  #lastMaintenance = -Infinity;
  #evictions = 0;

  constructor({ maxFailures = 5, windowMs = 15 * 60_000, lockoutMs = 15 * 60_000, maxTrackedKeys = 100_000, now = Date.now } = {}) {
    if (!(maxFailures >= 1) || !(maxTrackedKeys >= 1)) throw new RangeError('maxFailures and maxTrackedKeys must be positive');
    Object.assign(this, { maxFailures, windowMs, lockoutMs, maxTrackedKeys, now });
    this.#levels = Array.from({ length: maxFailures + 1 }, () => new Map());
  }

  isLocked(key) {
    const e = this.#entries.get(key);
    return !!e && e.lockedUntil > this.now();
  }

  /** Remaining lock in ms (0 if not locked). Use for the Retry-After header. */
  retryAfterMs(key) {
    const e = this.#entries.get(key);
    return e ? Math.max(0, e.lockedUntil - this.now()) : 0;
  }

  recordFailure(key) {
    const now = this.now();
    let e = this.#entries.get(key);
    if (!e) {
      if (this.#entries.size >= this.maxTrackedKeys) this.#makeRoom(now);
      e = { key, failures: 0, windowStart: now, lockedUntil: 0, level: 0 };
      this.#entries.set(key, e);
    }
    if (e.lockedUntil <= now && now - e.windowStart > this.windowMs) {
      e.windowStart = now;
      e.failures = 0;
    }
    e.failures++;
    let locked = false;
    if (e.failures >= this.maxFailures) {
      e.lockedUntil = now + this.lockoutMs;
      e.failures = 0;
      e.windowStart = now;
      locked = true;
    }
    this.#moveTo(e, e.lockedUntil > now ? this.maxFailures : e.failures);
    if (locked && this.#lockoutListener) {
      try {
        this.#lockoutListener(securityEvent(SecurityEventType.LOGIN_LOCKED, {
          principalId: key,
          category: OwaspCategory.AUTHENTICATION_FAILURES,
          detail: `${this.maxFailures} failures; locked for ${Math.round(this.lockoutMs / 1000)} s`,
        }));
      } catch {
        // A broken listener must never affect authentication.
      }
    }
  }

  /** Reports a LOGIN_LOCKED security event whenever a key becomes locked. */
  onLockout(listener) {
    this.#lockoutListener = listener;
    return this;
  }

  #lockoutListener = null;

  recordSuccess(key) {
    const e = this.#entries.get(key);
    if (!e) return;
    this.#entries.delete(key);
    this.#levels[e.level].delete(key);
  }

  /** Number of keys currently tracked (for monitoring). */
  get trackedKeys() {
    return this.#entries.size;
  }

  /** Entries evicted to stay under the cap since start. A steady rise means a flood: alert on it. */
  get evictionCount() {
    return this.#evictions;
  }

  #moveTo(e, level) {
    // Re-insert on every move and on every new lockout, so each level stays ordered by the time
    // of its last event and the oldest (first to expire) entry is always at the head.
    this.#levels[e.level].delete(e.key);
    e.level = level;
    this.#levels[level].set(e.key, e);
  }

  #isStale(e, now) {
    return e.lockedUntil <= now && now - e.windowStart > this.windowMs;
  }

  #makeRoom(now) {
    // Expired entries cost nothing to drop. The full scan runs at most once per second so a flood
    // cannot turn every failed login into an O(n) pass.
    if (now - this.#lastMaintenance >= MAINTENANCE_INTERVAL_MS) {
      this.#lastMaintenance = now;
      for (const [k, e] of this.#entries) {
        if (this.#isStale(e, now)) {
          this.#entries.delete(k);
          this.#levels[e.level].delete(k);
        }
      }
    }
    // Between scans, expired entries can still sit at the head of any level (for example a lockout
    // that has run out). Drop those from every level before evicting anything live.
    for (const level of this.#levels) {
      for (const [k, e] of level) {
        if (!this.#isStale(e, now)) break;
        level.delete(k);
        this.#entries.delete(k);
      }
    }
    // Still full: evict the weakest live entry, i.e. fewest failures, oldest first, lockouts last.
    for (const level of this.#levels) {
      for (const k of level.keys()) {
        if (this.#entries.size < this.maxTrackedKeys) return;
        level.delete(k);
        this.#entries.delete(k);
        this.#evictions++;
      }
    }
  }
}

const MAINTENANCE_INTERVAL_MS = 1000;
