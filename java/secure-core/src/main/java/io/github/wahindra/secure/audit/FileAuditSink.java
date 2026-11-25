package io.github.wahindra.secure.audit;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * Appends one line per record to a file you choose, rotating by size.
 *
 * <pre>
 * FileAuditSink.builder(Paths.get("/var/log/orders/security-audit.jsonl"))
 *         .maxBytes(50 * 1024 * 1024).maxFiles(20).hashChain(true).build();
 * </pre>
 *
 * <p>When the file reaches {@code maxBytes}, it is renamed to {@code name.1} (older files move to
 * {@code name.2} and so on, and the oldest beyond {@code maxFiles} is deleted). New files are
 * created readable and writable by the owner only on POSIX systems; on Windows they inherit the
 * directory's permissions, so choose a directory only the application can read.
 */
public final class FileAuditSink implements AuditSink {

    private final Path path;
    private final AuditFormat format;
    private final long maxBytes;
    private final int maxFiles;
    private final AuditChain chain;
    private OutputStream out;
    private long size;
    private String prev;

    private FileAuditSink(Builder b) throws IOException {
        this.path = b.path.toAbsolutePath();
        this.format = b.format;
        this.maxBytes = b.maxBytes;
        this.maxFiles = b.maxFiles;
        this.chain = b.hashChain ? new AuditChain(b.hmacKey) : null;
        if (chain != null && format == AuditFormat.CEF) {
            throw new IllegalArgumentException("the hash chain needs JSON lines: use format JSON or ECS for the file");
        }
        Path dir = path.getParent();
        if (dir != null) {
            Files.createDirectories(dir);
        }
        if (chain != null) {
            prev = lastHash(path);
            if (prev == null) {
                prev = lastHash(rotated(1));
            }
            if (prev == null) {
                prev = AuditChain.GENESIS;
            }
        }
        open();
    }

    public static Builder builder(Path path) {
        return new Builder(path);
    }

    @Override
    public synchronized void write(AuditRecord record) throws IOException {
        String line = format.format(record);
        String next = null;
        if (chain != null) {
            line = chain.link(prev, line);
            next = AuditChain.hashOf(line);
        }
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        if (maxBytes > 0 && size > 0 && size + bytes.length > maxBytes) {
            rotate();
        }
        out.write(bytes);
        size += bytes.length;
        if (next != null) {
            prev = next;
        }
    }

    @Override
    public synchronized void flush() throws IOException {
        out.flush();
    }

    @Override
    public synchronized void close() throws IOException {
        out.close();
    }

    public Path getPath() {
        return path;
    }

    private void open() throws IOException {
        if (!Files.exists(path)) {
            try {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } catch (UnsupportedOperationException notPosix) {
                Files.createFile(path);
            }
        }
        size = Files.size(path);
        out = new BufferedOutputStream(Files.newOutputStream(path, StandardOpenOption.APPEND), 8192);
    }

    private void rotate() throws IOException {
        out.close();
        Files.deleteIfExists(rotated(maxFiles));
        for (int i = maxFiles - 1; i >= 1; i--) {
            Path from = rotated(i);
            if (Files.exists(from)) {
                Files.move(from, rotated(i + 1), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        if (maxFiles > 0) {
            Files.move(path, rotated(1), StandardCopyOption.REPLACE_EXISTING);
        } else {
            Files.delete(path);
        }
        open();
    }

    private Path rotated(int n) {
        return path.resolveSibling(path.getFileName() + "." + n);
    }

    /** The hash at the end of an existing file, so the chain continues after a restart. */
    private static String lastHash(Path file) throws IOException {
        if (!Files.isRegularFile(file)) {
            return null;
        }
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            long len = raf.length();
            int n = (int) Math.min(len, 64 * 1024);
            byte[] tail = new byte[n];
            raf.seek(len - n);
            raf.readFully(tail);
            String text = new String(tail, StandardCharsets.UTF_8).trim();
            int nl = text.lastIndexOf('\n');
            return AuditChain.hashOf(nl < 0 ? text : text.substring(nl + 1).trim());
        }
    }

    public static final class Builder {
        private final Path path;
        private AuditFormat format = AuditFormat.JSON;
        private long maxBytes = 10L * 1024 * 1024;
        private int maxFiles = 10;
        private boolean hashChain;
        private byte[] hmacKey;

        private Builder(Path path) {
            if (path == null) {
                throw new IllegalArgumentException("path");
            }
            this.path = path;
        }

        /** {@link AuditFormat#JSON} (default), {@code ECS} or {@code CEF}. */
        public Builder format(AuditFormat v) { format = v; return this; }
        /** Rotate when the file would grow past this size; 0 never rotates. Default 10 MB. */
        public Builder maxBytes(long v) {
            if (v < 0) {
                throw new IllegalArgumentException("maxBytes");
            }
            maxBytes = v;
            return this;
        }
        /** Rotated files to keep ({@code name.1} ... {@code name.N}). Default 10. */
        public Builder maxFiles(int v) {
            if (v < 0) {
                throw new IllegalArgumentException("maxFiles");
            }
            maxFiles = v;
            return this;
        }
        /** Add {@code prev}/{@code hash} to every line; check with {@code secure audit verify}. */
        public Builder hashChain(boolean v) { hashChain = v; return this; }
        /** Use HMAC-SHA256 with this key (at least 16 bytes) instead of plain SHA-256. Implies the chain. */
        public Builder hmacKey(byte[] v) {
            hmacKey = v == null ? null : v.clone();
            hashChain = hashChain || v != null;
            return this;
        }

        public FileAuditSink build() throws IOException {
            return new FileAuditSink(this);
        }
    }
}
