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
 *
 * <p><b>Capacity.</b> At most {@code maxTrackedKeys} keys are kept. Only entries whose window and
 * lockout have both expired are ever removed; live failure counters are never evicted, because
 * evicting them would let an attacker reset a victim's counter by flooding the limiter with
 * throwaway keys. When the limiter is full of live entries it <b>fails closed</b>: keys it is not
 * already tracking are reported as locked until expired entries free space (at most one window).
 * During such a flood, new accounts are throttled but brute-force protection never switches off.
 * Size {@code maxTrackedKeys} for your traffic and alert on {@link #isSaturated()}.
 */
public final class LoginAttemptLimiter {

    private static final class Entry {
        int failures;
        long windowStart;
        long lockedUntil;
    }

    private static final long MAINTENANCE_INTERVAL_MS = 1000;

    private final int maxFailures;
    private final long windowMillis;
    private final long lockMillis;
    private final int maxTrackedKeys;
    private final Clock clock;
    private final Map<String, Entry> entries = new ConcurrentHashMap<String, Entry>();
    private final AtomicLong lastMaintenance = new AtomicLong(Long.MIN_VALUE / 2);

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
        long now = clock.millis();
        Entry e = entries.get(key);
        if (e == null) {
            return !hasRoom(now);
        }
        synchronized (e) {
            return e.lockedUntil > now;
        }
    }

    /** Remaining lock time, zero if not locked. Use for the Retry-After header. */
    public Duration retryAfter(String key) {
        long now = clock.millis();
        Entry e = entries.get(key);
        if (e == null) {
            return hasRoom(now) ? Duration.ZERO : Duration.ofMillis(windowMillis);
        }
        synchronized (e) {
            return Duration.ofMillis(Math.max(0, e.lockedUntil - now));
        }
    }

    public void recordFailure(String key) {
        long now = clock.millis();
        Entry e = entries.get(key);
        if (e == null) {
            if (!hasRoom(now)) {
                // Saturated: the key is already reported as locked by isLocked(), so the caller
                // should not have verified a password for it. Nothing to record.
                return;
            }
            Entry fresh = new Entry();
            fresh.windowStart = now;
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

    /** {@code true} while the limiter is full of live entries and fails closed for new keys. */
    public boolean isSaturated() {
        return !hasRoom(clock.millis());
    }

    /** Number of keys currently tracked (for monitoring). */
    public int trackedKeys() {
        return entries.size();
    }

    /**
     * Whether a new key can be tracked. When full, removes expired entries; the scan runs at
     * most once per {@link #MAINTENANCE_INTERVAL_MS} so a flood of new keys cannot turn every
     * request into an O(n) scan.
     */
    private boolean hasRoom(long now) {
        if (entries.size() < maxTrackedKeys) {
            return true;
        }
        long last = lastMaintenance.get();
        if (now - last >= MAINTENANCE_INTERVAL_MS && lastMaintenance.compareAndSet(last, now)) {
            for (Iterator<Map.Entry<String, Entry>> it = entries.entrySet().iterator(); it.hasNext(); ) {
                Entry e = it.next().getValue();
                synchronized (e) {
                    if (e.lockedUntil <= now && now - e.windowStart > windowMillis) {
                        it.remove();
                    }
                }
            }
        }
        return entries.size() < maxTrackedKeys;
    }
}
