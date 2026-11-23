package io.github.wahindra.secure.crypto;

import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
        if (entries.size() >= maxTrackedKeys) {
            purgeExpired(now);
        }
        Entry e = entries.get(key);
        if (e == null) {
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

    private void purgeExpired(long now) {
        for (Iterator<Map.Entry<String, Entry>> it = entries.entrySet().iterator(); it.hasNext(); ) {
            Entry e = it.next().getValue();
            synchronized (e) {
                if (e.lockedUntil <= now && now - e.windowStart > windowMillis) {
                    it.remove();
                }
            }
        }
    }
}
