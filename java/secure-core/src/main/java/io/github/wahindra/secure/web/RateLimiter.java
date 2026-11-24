package io.github.wahindra.secure.web;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Token-bucket rate limiting per key (client IP, user id, API key...), for any endpoint. Each key
 * may make {@code capacity} requests in a burst, refilled at {@code capacity / period}.
 *
 * <pre>
 * RateLimiter api = RateLimiter.perMinute(120);                    // 120 requests a minute per key
 * RateLimiter.Decision d = api.tryAcquire(clientIp);
 * if (!d.isAllowed()) { response.setStatus(429); response.setHeader("Retry-After", d.retryAfterSeconds()); }
 * </pre>
 *
 * <p>Memory is bounded: at most {@code maxKeys} keys are kept, and the least recently seen key is
 * forgotten first. Forgetting a key only gives that key a fresh bucket; it never blocks anyone.
 * For several instances, use the same limits in a shared store, or divide the limit by the
 * number of instances.
 *
 * <p>Use the real client address. Behind a proxy, take it from the proxy's trusted header, not
 * from a client-supplied {@code X-Forwarded-For}, or every client can choose its own key.
 */
public final class RateLimiter {

    /** Result of one {@link #tryAcquire} call. */
    public static final class Decision {
        private final boolean allowed;
        private final int limit;
        private final int remaining;
        private final long retryAfterMillis;
        private final long resetMillis;

        Decision(boolean allowed, int limit, int remaining, long retryAfterMillis, long resetMillis) {
            this.allowed = allowed;
            this.limit = limit;
            this.remaining = remaining;
            this.retryAfterMillis = retryAfterMillis;
            this.resetMillis = resetMillis;
        }

        public boolean isAllowed() { return allowed; }
        public int getLimit() { return limit; }
        public int getRemaining() { return remaining; }
        /** 0 when allowed; otherwise how long until one more request is allowed. */
        public long getRetryAfterMillis() { return retryAfterMillis; }
        /** For the {@code Retry-After} header (whole seconds, rounded up). */
        public String retryAfterSeconds() { return String.valueOf((retryAfterMillis + 999) / 1000); }

        /** IETF RateLimit header fields plus Retry-After when limited. */
        public Map<String, String> headers() {
            Map<String, String> h = new LinkedHashMap<String, String>();
            h.put("RateLimit-Limit", String.valueOf(limit));
            h.put("RateLimit-Remaining", String.valueOf(remaining));
            h.put("RateLimit-Reset", String.valueOf((resetMillis + 999) / 1000));
            if (!allowed) {
                h.put("Retry-After", retryAfterSeconds());
            }
            return h;
        }
    }

    private static final class Bucket {
        double tokens;
        long updated;
    }

    private final int capacity;
    private final double tokensPerMilli;
    private final int maxKeys;
    private final Clock clock;
    private final LinkedHashMap<String, Bucket> buckets;

    public RateLimiter(int capacity, Duration period, int maxKeys, Clock clock) {
        if (capacity < 1 || maxKeys < 1 || period.isZero() || period.isNegative()) {
            throw new IllegalArgumentException("capacity, period and maxKeys must be positive");
        }
        this.capacity = capacity;
        this.tokensPerMilli = (double) capacity / period.toMillis();
        this.maxKeys = maxKeys;
        this.clock = clock;
        this.buckets = new LinkedHashMap<String, Bucket>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
                return size() > RateLimiter.this.maxKeys;
            }
        };
    }

    public static RateLimiter perSecond(int requests) {
        return new RateLimiter(requests, Duration.ofSeconds(1), 100_000, Clock.systemUTC());
    }

    public static RateLimiter perMinute(int requests) {
        return new RateLimiter(requests, Duration.ofMinutes(1), 100_000, Clock.systemUTC());
    }

    /** Takes one token for {@code key} if available. A {@code null} key shares one bucket. */
    public synchronized Decision tryAcquire(String key) {
        long now = clock.millis();
        String k = key == null ? "" : key;
        Bucket b = buckets.get(k);
        if (b == null) {
            b = new Bucket();
            b.tokens = capacity;
            b.updated = now;
            buckets.put(k, b);
        } else if (now > b.updated) {
            b.tokens = Math.min(capacity, b.tokens + (now - b.updated) * tokensPerMilli);
            b.updated = now;
        }
        boolean allowed = b.tokens >= 1;
        if (allowed) {
            b.tokens -= 1;
        }
        // Time until the bucket is full again, measured after this request.
        long resetMillis = (long) Math.ceil((capacity - b.tokens) / tokensPerMilli);
        if (allowed) {
            return new Decision(true, capacity, (int) Math.floor(b.tokens), 0, resetMillis);
        }
        long retry = (long) Math.ceil((1 - b.tokens) / tokensPerMilli);
        return new Decision(false, capacity, 0, retry, resetMillis);
    }

    /** Number of keys currently tracked (for monitoring). */
    public synchronized int trackedKeys() {
        return buckets.size();
    }

    public int getCapacity() {
        return capacity;
    }
}
