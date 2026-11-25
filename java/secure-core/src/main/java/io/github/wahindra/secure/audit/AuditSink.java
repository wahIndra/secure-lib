package io.github.wahindra.secure.audit;

import java.io.Closeable;
import java.io.IOException;

/**
 * Where {@link AuditLog} writes records: {@link FileAuditSink}, {@link SyslogAuditSink}, or your
 * own (Kafka, a webhook, a database). Called from the audit log's single writer thread, never from
 * a request thread, so a slow or failing sink cannot delay or break requests.
 */
public interface AuditSink extends Closeable {

    /** Writes one record. An exception counts as a failed write; the record is not retried. */
    void write(AuditRecord record) throws IOException;

    /** Called when the queue is empty, so buffered records reach the destination. */
    default void flush() throws IOException {
    }

    @Override
    default void close() throws IOException {
    }
}
