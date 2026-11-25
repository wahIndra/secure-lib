package io.github.wahindra.secure.audit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tamper evidence for JSON audit lines. Each line ends with {@code "prev"} (the hash of the line
 * before) and {@code "hash"}: SHA-256, or HMAC-SHA256 with a key, over {@code prev + "\n" + line}.
 * Changing, removing or reordering a line breaks the chain, and {@link #verify} reports where.
 *
 * <p>Without a key, someone who can write the file can also recompute every hash; the chain then
 * only catches careless edits. With a key kept away from the log host, they cannot. Neither
 * detects removal of the newest lines, so also send the records to a SIEM.
 */
public final class AuditChain {

    /** {@code prev} of the very first record. */
    public static final String GENESIS = "0000000000000000000000000000000000000000000000000000000000000000";

    static final Pattern SUFFIX = Pattern.compile(",\"prev\":\"([0-9a-f]{64})\",\"hash\":\"([0-9a-f]{64})\"}$");

    private final byte[] key;

    /** @param key HMAC key, or {@code null} for plain SHA-256 */
    public AuditChain(byte[] key) {
        if (key != null && key.length < 16) {
            throw new IllegalArgumentException("HMAC key must be at least 16 bytes");
        }
        this.key = key == null ? null : key.clone();
    }

    /** The hash of a line (JSON object, without chain fields) following {@code prev}. */
    public String hash(String prev, String line) {
        byte[] data = (prev + "\n" + line).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] h;
            if (key == null) {
                h = MessageDigest.getInstance("SHA-256").digest(data);
            } else {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
                h = mac.doFinal(data);
            }
            StringBuilder sb = new StringBuilder(64);
            for (byte b : h) {
                sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            }
            return sb.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 / HmacSHA256 unavailable", e);
        }
    }

    /** {@code line} with {@code prev} and {@code hash} added as its last two fields. */
    public String link(String prev, String line) {
        if (!line.startsWith("{") || !line.endsWith("}")) {
            throw new IllegalArgumentException("the hash chain needs JSON lines (format JSON or ECS)");
        }
        return line.substring(0, line.length() - 1) + ",\"prev\":\"" + prev + "\",\"hash\":\"" + hash(prev, line) + "\"}";
    }

    /** The {@code hash} of a chained line, or {@code null} if it has none. */
    static String hashOf(String chainedLine) {
        Matcher m = SUFFIX.matcher(chainedLine);
        return m.find() ? m.group(2) : null;
    }

    /** Checks one or more files, oldest first (e.g. {@code audit.log.2 audit.log.1 audit.log}). */
    public Result verify(List<Path> files) throws IOException {
        List<String> problems = new ArrayList<String>();
        List<String> notes = new ArrayList<String>();
        String last = null;
        long records = 0;
        for (Path file : files) {
            try (BufferedReader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String line;
                int n = 0;
                while ((line = in.readLine()) != null) {
                    n++;
                    if (line.isEmpty()) {
                        continue;
                    }
                    records++;
                    String where = file.getFileName() + ":" + n + ": ";
                    Matcher m = SUFFIX.matcher(line);
                    if (!m.find()) {
                        problems.add(where + "no hash: written without the chain, cut off, or edited");
                        last = null;
                        continue;
                    }
                    String prev = m.group(1);
                    String hash = m.group(2);
                    String base = line.substring(0, m.start()) + "}";
                    if (!hash(prev, base).equals(hash)) {
                        problems.add(where + "hash does not match: this record was changed"
                                + (key == null ? "" : " (or the key is wrong)"));
                    } else if (last == null && records == 1 && !GENESIS.equals(prev)) {
                        notes.add(where + "continues an earlier file (prev " + prev.substring(0, 12) + "...)");
                    } else if (GENESIS.equals(prev) && records > 1) {
                        notes.add(where + "the chain starts again here (log reopened without the previous hash)");
                    } else if (last != null && !prev.equals(last)) {
                        problems.add(where + "does not follow the previous record: records before it were removed or reordered");
                    }
                    last = hash;
                }
            }
        }
        return new Result(records, problems, notes, last);
    }

    /** Outcome of {@link #verify}. */
    public static final class Result {
        private final long records;
        private final List<String> problems;
        private final List<String> notes;
        private final String lastHash;

        Result(long records, List<String> problems, List<String> notes, String lastHash) {
            this.records = records;
            this.problems = Collections.unmodifiableList(problems);
            this.notes = Collections.unmodifiableList(notes);
            this.lastHash = lastHash;
        }

        public boolean isIntact() { return problems.isEmpty(); }
        public long getRecords() { return records; }
        /** {@code file:line: what is wrong}. */
        public List<String> getProblems() { return problems; }
        /** Things worth knowing that are not tampering, e.g. a file that continues an earlier one. */
        public List<String> getNotes() { return notes; }
        /** Hash of the newest record. Compare it with the copy in your SIEM to detect a cut-off tail. */
        public String getLastHash() { return lastHash; }
    }
}
