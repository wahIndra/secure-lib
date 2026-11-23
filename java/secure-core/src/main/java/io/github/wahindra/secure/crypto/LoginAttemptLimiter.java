package io.github.wahindra.secure.crypto;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory brute-force / credential-stuffing protection. Key by account and, separately, by
 * client IP. For clusters, back this with a shared store (Redis) using the same rules.
 *
 * <pre>
 * if (limiter.isLocked(username)) return tooManyRequests(limiter.retryAfter(username));
 * if (ok) limiter.recordSuccess(username); else limiter.recordFailure(username);
 * </pre>
 *
 * <p><b>Bounded memory without blocking anyone.</b> At most {@code maxTrackedKeys} keys are kept.
 * Expired entries are dropped first. If the limiter is still full, it evicts the entry with the
 * <i>fewest</i> live failures (oldest first), and active lockouts only after every unlocked entry.
 * Unknown keys are never refused, so a flood of throwaway usernames cannot lock out real users.
 *
 * <p>The cost of an attack is what keeps this safe. To evict a victim holding {@code k} failures, an
 * attacker must first fill the whole table with entries holding at least {@code k} failures each:
 * at least {@code k * maxTrackedKeys} failed attempts, to win back {@code k} guesses. That is at
 * most one extra guess per {@code maxTrackedKeys} (default 100,000) attacker requests. Put a
 * per-IP limiter in front so a single source cannot generate that volume at all.
 *
 * <p>Use <b>separate instances</b> for accounts and for client IPs, so a flood of one kind of key
 * cannot push the other kind out.
 *
 * <p>Why not refuse new keys when full instead? Then a flood of throwaway usernames would lock out
 * every account the limiter is not already tracking: a cheap, total login outage. Bounded
 * eviction costs an attacker far more than it gains, while refusal costs them almost nothing.
 */
public final class LoginAttemptLimiter {

    private static final class Entry {
        final String key;
        int failures;
        long windowStart;
        long lockedUntil;
        /** Index into {@link #levels}: failures while unlocked, {@code maxFailures} once locked. */
        int level;

        Entry(String key) {
            this.key = key;
        }
    }

    private static final long MAINTENANCE_INTERVAL_MS = 1000;

    private final int maxFailures;
    private final long windowMillis;
    private final long lockMillis;
    private final int maxTrackedKeys;
    private final Clock clock;

    // Guarded by "this". Login checks are rare compared with request handling, so one lock is simpler
    // and safer than fine-grained concurrency here.
    private final Map<String, Entry> entries = new HashMap<String, Entry>();
    /** levels[n] holds entries at that level in the order they reached it (oldest first). */
    private final LinkedHashMap<String, Entry>[] levels;
    private long lastMaintenance = Long.MIN_VALUE / 2;
    private long evictions;

    public LoginAttemptLimiter() {
        this(5, Duration.ofMinutes(15), Duration.ofMinutes(15), 100_000, Clock.systemUTC());
    }

    @SuppressWarnings("unchecked")
    public LoginAttemptLimiter(int maxFailures, Duration window, Duration lockout, int maxTrackedKeys, Clock clock) {
        if (maxFailures < 1 || maxTrackedKeys < 1) {
            throw new IllegalArgumentException("maxFailures and maxTrackedKeys must be positive");
        }
        this.maxFailures = maxFailures;
        this.windowMillis = window.toMillis();
        this.lockMillis = lockout.toMillis();
        this.maxTrackedKeys = maxTrackedKeys;
        this.clock = clock;
        this.levels = new LinkedHashMap[maxFailures + 1];
        for (int i = 0; i < levels.length; i++) {
            levels[i] = new LinkedHashMap<String, Entry>();
        }
    }

    public synchronized boolean isLocked(String key) {
        Entry e = entries.get(key);
        return e != null && e.lockedUntil > clock.millis();
    }

    /** Remaining lock time, zero if not locked. Use for the Retry-After header. */
    public synchronized Duration retryAfter(String key) {
        Entry e = entries.get(key);
        return e == null ? Duration.ZERO : Duration.ofMillis(Math.max(0, e.lockedUntil - clock.millis()));
    }

    public synchronized void recordFailure(String key) {
        long now = clock.millis();
        Entry e = entries.get(key);
        if (e == null) {
            if (entries.size() >= maxTrackedKeys) {
                makeRoom(now);
            }
            e = new Entry(key);
            e.windowStart = now;
            entries.put(key, e);
        }
        if (e.lockedUntil <= now && now - e.windowStart > windowMillis) {
            e.windowStart = now;
            e.failures = 0;
        }
        e.failures++;
        if (e.failures >= maxFailures) {
            e.lockedUntil = now + lockMillis;
            e.failures = 0;
            e.windowStart = now;
        }
        moveTo(e, e.lockedUntil > now ? maxFailures : e.failures);
    }

    public synchronized void recordSuccess(String key) {
        Entry e = entries.remove(key);
        if (e != null) {
            levels[e.level].remove(key);
        }
    }

    /** Number of keys currently tracked (for monitoring). */
    public synchronized int trackedKeys() {
        return entries.size();
    }

    /** Entries evicted to stay under the cap since start. A steady rise means a flood: alert on it. */
    public synchronized long evictionCount() {
        return evictions;
    }

    private void moveTo(Entry e, int level) {
        // Re-insert on every move and on every new lockout, so each level stays ordered by the
        // time of its last event and the oldest (first to expire) entry is always at the head.
        levels[e.level].remove(e.key);
        e.level = level;
        levels[level].put(e.key, e);
    }

    private boolean isStale(Entry e, long now) {
        return e.lockedUntil <= now && now - e.windowStart > windowMillis;
    }

    private void makeRoom(long now) {
        // Expired entries cost nothing to drop. The full scan runs at most once per interval so a
        // flood cannot turn every failed login into an O(n) pass.
        if (now - lastMaintenance >= MAINTENANCE_INTERVAL_MS) {
            lastMaintenance = now;
            for (Iterator<Entry> it = entries.values().iterator(); it.hasNext(); ) {
                Entry e = it.next();
                if (isStale(e, now)) {
                    it.remove();
                    levels[e.level].remove(e.key);
                }
            }
        }
        // Between scans, expired entries can still sit at the head of any level (for example a
        // lockout that has run out). Drop those from every level before evicting anything live.
        for (LinkedHashMap<String, Entry> level : levels) {
            Iterator<Entry> it = level.values().iterator();
            while (it.hasNext()) {
                Entry head = it.next();
                if (!isStale(head, now)) {
                    break;
                }
                it.remove();
                entries.remove(head.key);
            }
        }
        // Still full: evict the weakest live entry, i.e. fewest failures, oldest first, lockouts last.
        for (int level = 0; level < levels.length && entries.size() >= maxTrackedKeys; level++) {
            Iterator<Entry> it = levels[level].values().iterator();
            while (it.hasNext() && entries.size() >= maxTrackedKeys) {
                Entry victim = it.next();
                it.remove();
                entries.remove(victim.key);
                evictions++;
            }
        }
    }
}
