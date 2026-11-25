package io.github.wahindra.secure.audit;

import io.github.wahindra.secure.web.SecurityEvent;
import io.github.wahindra.secure.web.SecurityEventListener;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An audit trail of security events and application actions, written to a file, a syslog / SIEM
 * collector, or your own {@link AuditSink}.
 *
 * <pre>
 * AuditLog audit = AuditLog.builder()
 *         .sink(FileAuditSink.builder(Paths.get("/var/log/orders/security-audit.jsonl")).hashChain(true).build())
 *         .sink(SyslogAuditSink.builder("siem.example.com", 6514).protocol(SyslogAuditSink.Protocol.TLS).build())
 *         .build();
 *
 * SecurityFilterEngine.builder().listener(audit)...            // blocked requests, rate limits, CORS...
 * new LoginAttemptLimiter().onLockout(audit).onAttempt(audit);  // logins
 * audit.record("order.refund", user.getId(), "order/42", AuditRecord.Outcome.SUCCESS);
 * </pre>
 *
 * <p>Recording never blocks and never throws: records go into a bounded queue and one background
 * thread writes them. When the queue is full (a destination is down or too slow), new records are
 * dropped and counted in {@link #droppedCount()}, and a warning is logged. Alert on that counter.
 */
public final class AuditLog implements SecurityEventListener, Closeable {

    private static final Logger LOG = Logger.getLogger(AuditLog.class.getName());

    private final List<AuditSink> sinks;
    private final BlockingQueue<AuditRecord> queue;
    private final Thread writer;
    private final Thread shutdownHook;
    private final boolean[] failing;
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong failedWrites = new AtomicLong();
    private final Object progress = new Object();
    private long processed; // guarded by progress
    private volatile boolean closed;

    private AuditLog(Builder b) {
        if (b.sinks.isEmpty()) {
            throw new IllegalArgumentException("add at least one sink: FileAuditSink, SyslogAuditSink or your own");
        }
        this.sinks = Collections.unmodifiableList(new ArrayList<AuditSink>(b.sinks));
        this.failing = new boolean[sinks.size()];
        this.queue = new ArrayBlockingQueue<AuditRecord>(b.queueCapacity);
        this.writer = new Thread(this::run, "secure-audit-writer");
        writer.setDaemon(true);
        writer.start();
        if (b.closeOnShutdown) {
            shutdownHook = new Thread(this::close, "secure-audit-shutdown");
            Runtime.getRuntime().addShutdownHook(shutdownHook);
        } else {
            shutdownHook = null;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Records a library security event; register the audit log as a {@link SecurityEventListener}. */
    @Override
    public void onEvent(SecurityEvent event) {
        record(AuditRecord.of(event));
    }

    /**
     * Queues a record.
     *
     * @return {@code false} if it was dropped (queue full or log closed)
     */
    public boolean record(AuditRecord record) {
        if (record == null) {
            return false;
        }
        if (closed || !queue.offer(record)) {
            long n = dropped.incrementAndGet();
            if (n == 1 || n % 1000 == 0) {
                LOG.warning("audit log: " + n + " record(s) dropped so far (" + (closed ? "closed" : "queue full") + ")");
            }
            return false;
        }
        accepted.incrementAndGet();
        return true;
    }

    /** An application action, e.g. {@code record("user.role.change", adminId, "user/17", SUCCESS)}. */
    public boolean record(String event, String principalId, String resource, AuditRecord.Outcome outcome) {
        return record(AuditRecord.builder(event).principalId(principalId).resource(resource).outcome(outcome).build());
    }

    /** Waits until every queued record was handed to the sinks and flushed. */
    public boolean flush(Duration timeout) {
        long target = accepted.get();
        long deadline = System.nanoTime() + timeout.toNanos();
        synchronized (progress) {
            while (processed < target) {
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    return false;
                }
                try {
                    TimeUnit.NANOSECONDS.timedWait(progress, left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return true;
    }

    /** Records dropped because the queue was full or the log was closed. */
    public long droppedCount() {
        return dropped.get();
    }

    /** Writes that failed in some sink (each failing sink counts once per record). */
    public long failedWriteCount() {
        return failedWrites.get();
    }

    /** Records waiting to be written. */
    public int queued() {
        return queue.size();
    }

    /** Writes what is queued (up to 5 seconds), then closes the sinks. Later records are dropped. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            writer.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        for (AuditSink s : sinks) {
            try {
                s.flush();
                s.close();
            } catch (Exception e) {
                LOG.log(Level.WARNING, "audit sink failed to close: " + e.getClass().getSimpleName());
            }
        }
        if (shutdownHook != null && Thread.currentThread() != shutdownHook) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException alreadyShuttingDown) {
                // fine
            }
        }
    }

    private void run() {
        while (true) {
            AuditRecord r;
            try {
                r = queue.poll(200, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                r = null;
            }
            if (r == null) {
                if (closed) {
                    return;
                }
                continue;
            }
            for (int i = 0; i < sinks.size(); i++) {
                write(i, r);
            }
            if (queue.isEmpty()) {
                for (int i = 0; i < sinks.size(); i++) {
                    try {
                        sinks.get(i).flush();
                    } catch (Exception e) {
                        failed(i, e);
                    }
                }
            }
            synchronized (progress) {
                processed++;
                progress.notifyAll();
            }
        }
    }

    private void write(int i, AuditRecord r) {
        try {
            sinks.get(i).write(r);
            if (failing[i]) {
                failing[i] = false;
                LOG.info("audit sink " + sinks.get(i).getClass().getSimpleName() + " is writing again");
            }
        } catch (Exception e) {
            failedWrites.incrementAndGet();
            failed(i, e);
        }
    }

    private void failed(int i, Exception e) {
        if (!failing[i]) {
            failing[i] = true;
            LOG.warning("audit sink " + sinks.get(i).getClass().getSimpleName() + " failed: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + " (records are counted and dropped until it recovers)");
        }
    }

    public static final class Builder {
        private final List<AuditSink> sinks = new ArrayList<AuditSink>();
        private int queueCapacity = 10_000;
        private boolean closeOnShutdown = true;

        private Builder() {
        }

        public Builder sink(AuditSink sink) {
            if (sink == null) {
                throw new IllegalArgumentException("sink");
            }
            sinks.add(sink);
            return this;
        }

        /** Records held while sinks catch up; beyond this they are dropped. Default 10,000. */
        public Builder queueCapacity(int v) {
            if (v < 1) {
                throw new IllegalArgumentException("queueCapacity");
            }
            queueCapacity = v;
            return this;
        }

        /** Write what is queued when the JVM exits (default on). Turn off when a container closes it. */
        public Builder closeOnShutdown(boolean v) { closeOnShutdown = v; return this; }

        public AuditLog build() {
            return new AuditLog(this);
        }
    }
}
