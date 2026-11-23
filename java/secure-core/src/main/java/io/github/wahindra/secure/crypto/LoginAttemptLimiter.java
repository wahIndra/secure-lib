package io.github.wahindra.secure.crypto;

import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory brute-force / credential-stuffing protection. Key by account and, separately, by
 * client IP. For clusters, back this with a shared store (Redis) using the same rules.
 *
 * <pre>
 * if (limiter.isLocked(username)) return tooManyRequests(limiter.retryAfter(username));
 * if (ok) limiter.recordSuccess(username); else limiter.recordFailure(username);
 * </pre>
 */
public final class LoginAttemptLimiter {

    private static final class Entry {
        int failures;
        long windowStart;
        long lockedUntil;
    }

    private final int maxFailures;
    private final long windowMillis;
    private final long lockMillis;
    private final int maxTrackedKeys;
    private final Clock clock;
    private final Map<String, Entry> entries = new ConcurrentHashMap<String, Entry>();
    private final AtomicLong lastMaintenance = new AtomicLong(Long.MIN_VALUE / 2);

    private static final long MAINTENANCE_INTERVAL_MS = 1000;

    public LoginAttemptLimiter() {
        this(5, Duration.ofMinutes(15), Duration.ofMinutes(15), 100_000, Clock.systemUTC());
    }

    public LoginAttemptLimiter(int maxFailures, Duration window, Duration lockout, int maxTrackedKeys, Clock clock) {
        this.maxFailures = maxFailures;
        this.windowMillis = window.toMillis();
        this.lockMillis = lockout.toMillis();
        this.maxTrackedKeys = maxTrackedKeys;
        this.clock = clock;
    }

    public boolean isLocked(String key) {
        Entry e = entries.get(key);
        if (e == null) {
            return false;
        }
        synchronized (e) {
            return e.lockedUntil > clock.millis();
        }
    }

    /** Remaining lock time, zero if not locked. Use for the Retry-After header. */
    public Duration retryAfter(String key) {
        Entry e = entries.get(key);
        if (e == null) {
            return Duration.ZERO;
        }
        synchronized (e) {
            return Duration.ofMillis(Math.max(0, e.lockedUntil - clock.millis()));
        }
    }

    public void recordFailure(String key) {
        long now = clock.millis();
        Entry e = entries.get(key);
        if (e == null) {
            if (entries.size() >= maxTrackedKeys && !makeRoom(now)) {
                // Full of active lockouts: keep the memory cap hard rather than grow. Pair this
                // limiter with a per-IP one so a flood of usernames is still throttled.
                return;
            }
            Entry fresh = new Entry();
            e = entries.putIfAbsent(key, fresh);
            if (e == null) {
                e = fresh;
            }
        }
        synchronized (e) {
            if (now - e.windowStart > windowMillis) {
                e.windowStart = now;
                e.failures = 0;
            }
            e.failures++;
            if (e.failures >= maxFailures) {
                e.lockedUntil = now + lockMillis;
                e.failures = 0;
                e.windowStart = now;
            }
        }
    }

    public void recordSuccess(String key) {
        entries.remove(key);
    }

    /**
     * Frees space when the map is full. Full scans run at most once per {@link #MAINTENANCE_INTERVAL_MS}
     * so a flood of new keys cannot turn every failed login into an O(n) scan. Expired entries go
     * first, then unlocked ones; active lockouts are never evicted, otherwise an attacker could
     * unlock a victim by flooding the limiter with throwaway usernames.
     *
     * @return {@code true} if there is room for a new key
     */
    private boolean makeRoom(long now) {
        long last = lastMaintenance.get();
        if (now - last < MAINTENANCE_INTERVAL_MS || !lastMaintenance.compareAndSet(last, now)) {
            return entries.size() < maxTrackedKeys;
        }
        int target = maxTrackedKeys - Math.max(1, maxTrackedKeys / 10);
        boolean expiredOnly = true;
        for (int pass = 0; pass < 2 && entries.size() > target; pass++) {
            for (Iterator<Map.Entry<String, Entry>> it = entries.entrySet().iterator(); it.hasNext() && entries.size() > target; ) {
                Entry e = it.next().getValue();
                synchronized (e) {
                    boolean locked = e.lockedUntil > now;
                    boolean expired = !locked && now - e.windowStart > windowMillis;
                    if (expired || (!expiredOnly && !locked)) {
                        it.remove();
                    }
                }
            }
            expiredOnly = false;
        }
        return entries.size() < maxTrackedKeys;
    }

    /** Number of keys currently tracked (for monitoring). */
    public int trackedKeys() {
        return entries.size();
    }
}
