package io.github.wahindra.secure;

import io.github.wahindra.secure.audit.AuditChain;
import io.github.wahindra.secure.audit.AuditFormat;
import io.github.wahindra.secure.audit.AuditLog;
import io.github.wahindra.secure.audit.AuditRecord;
import io.github.wahindra.secure.audit.AuditSink;
import io.github.wahindra.secure.audit.FileAuditSink;
import io.github.wahindra.secure.audit.SyslogAuditSink;
import io.github.wahindra.secure.crypto.LoginAttemptLimiter;
import io.github.wahindra.secure.devtools.SecureCli;
import io.github.wahindra.secure.web.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditTest {

    @TempDir
    Path dir;

    private static AuditRecord rec(String event) {
        return AuditRecord.builder(event).timestamp(Instant.EPOCH).build();
    }

    @Test
    void auditLinesMatchTheSharedVectorsInEveryFormat() throws IOException {
        List<AuditVectors.Case> cases = AuditVectors.load(AuditVectors.file());
        assertTrue(cases.size() >= 10);
        AuditChain sha = new AuditChain(null);
        AuditChain hmac = new AuditChain(AuditVectors.HMAC_KEY.getBytes(StandardCharsets.UTF_8));
        String prev = AuditChain.GENESIS;
        String prevHmac = AuditChain.GENESIS;
        for (AuditVectors.Case c : cases) {
            AuditRecord r = AuditVectors.build(c);
            assertEquals(c.out("json"), AuditFormat.JSON.format(r), c.name() + " / json");
            assertEquals(c.out("ecs"), AuditFormat.ECS.format(r), c.name() + " / ecs");
            assertEquals(c.out("cef"), AuditFormat.CEF.format(r), c.name() + " / cef");
            String linked = sha.link(prev, c.out("json"));
            assertEquals(c.out("chained"), linked, c.name() + " / chain");
            prev = linked.substring(linked.length() - 66, linked.length() - 2);
            String linkedHmac = hmac.link(prevHmac, c.out("json"));
            assertEquals(c.out("chainedHmac"), linkedHmac, c.name() + " / hmac chain");
            prevHmac = linkedHmac.substring(linkedHmac.length() - 66, linkedHmac.length() - 2);
        }
    }

    @Test
    void recordsAreSanitized() {
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < 5000; i++) {
            big.append('z');
        }
        AuditRecord r = AuditRecord.builder("x").principalId("p\r\nINJECTED").detail("a\nb password=hunter2 " + big).build();
        String line = AuditFormat.JSON.format(r);
        assertFalse(line.contains("\n") || line.contains("\r"));
        assertFalse(line.contains("hunter2"));
        assertTrue(r.getDetail().length() < 1100);
        assertThrows(IllegalArgumentException.class, () -> AuditRecord.builder(" "));
        assertThrows(IllegalArgumentException.class, () -> AuditRecord.builder("x").severity(11));
        assertEquals(AuditFormat.CEF, AuditFormat.parse(" cef "));
    }

    @Test
    void fileSinkAppendsLinesToTheChosenPathOwnerOnly() throws IOException {
        Path file = dir.resolve("nested/security-audit.jsonl");
        try (FileAuditSink sink = FileAuditSink.builder(file).build()) {
            sink.write(rec("a"));
            sink.write(rec("b"));
        }
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        assertEquals(2, lines.size());
        assertTrue(lines.get(1).contains("\"event\":\"b\""));
        if (file.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertEquals(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), Files.getPosixFilePermissions(file));
        }
    }

    @Test
    void fileSinkRotatesBySizeAndKeepsMaxFiles() throws IOException {
        Path file = dir.resolve("a.log");
        try (FileAuditSink sink = FileAuditSink.builder(file).maxBytes(400).maxFiles(2).build()) {
            for (int i = 0; i < 20; i++) {
                sink.write(AuditRecord.builder("e" + i).timestamp(Instant.EPOCH).detail(String.join("", Collections.nCopies(100, "x"))).build());
            }
        }
        assertTrue(Files.exists(dir.resolve("a.log.1")) && Files.exists(dir.resolve("a.log.2")));
        assertFalse(Files.exists(dir.resolve("a.log.3")));
        for (String f : new String[] {"a.log", "a.log.1", "a.log.2"}) {
            assertTrue(Files.size(dir.resolve(f)) <= 400, f);
        }
        assertTrue(new String(Files.readAllBytes(file), StandardCharsets.UTF_8).contains("\"event\":\"e19\""));
    }

    @Test
    void hashChainCatchesEditedRemovedAndReorderedRecords() throws IOException {
        Path file = dir.resolve("audit.jsonl");
        try (FileAuditSink sink = FileAuditSink.builder(file).hashChain(true).build()) {
            for (int i = 0; i < 5; i++) {
                sink.write(rec("e" + i));
            }
        }
        AuditChain chain = new AuditChain(null);
        assertTrue(chain.verify(Collections.singletonList(file)).isIntact());
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);

        List<String> edited = new ArrayList<String>(lines);
        edited.set(2, edited.get(2).replace("\"e2\"", "\"e9\""));
        Files.write(file, edited, StandardCharsets.UTF_8);
        assertTrue(chain.verify(Collections.singletonList(file)).getProblems().get(0).startsWith("audit.jsonl:3: hash does not match"));

        Files.write(file, Arrays.asList(lines.get(0), lines.get(1), lines.get(3), lines.get(4)), StandardCharsets.UTF_8);
        assertTrue(chain.verify(Collections.singletonList(file)).getProblems().get(0).startsWith("audit.jsonl:3: does not follow"));

        Files.write(file, Arrays.asList(lines.get(1), lines.get(0), lines.get(2)), StandardCharsets.UTF_8);
        assertFalse(chain.verify(Collections.singletonList(file)).isIntact());
    }

    @Test
    void hashChainContinuesAcrossRestartAndRotation() throws IOException {
        Path file = dir.resolve("audit.jsonl");
        for (String run : new String[] {"a", "b"}) {
            try (FileAuditSink sink = FileAuditSink.builder(file).hashChain(true).maxBytes(600).maxFiles(10).build()) {
                for (int i = 0; i < 4; i++) {
                    sink.write(rec(run + i));
                }
            }
        }
        List<Path> files = new ArrayList<Path>();
        for (int n = 10; n >= 1; n--) {
            Path p = dir.resolve("audit.jsonl." + n);
            if (Files.exists(p)) {
                files.add(p);
            }
        }
        files.add(file);
        assertTrue(files.size() > 1, "rotated");
        AuditChain.Result r = new AuditChain(null).verify(files);
        assertTrue(r.isIntact(), r.getProblems().toString());
        assertEquals(8, r.getRecords());
        assertTrue(r.getNotes().isEmpty(), r.getNotes().toString());
        assertEquals(1, new AuditChain(null).verify(Collections.singletonList(file)).getNotes().size());
    }

    @Test
    void hmacChainNeedsTheKeyAndCefCannotBeChained() throws IOException {
        Path file = dir.resolve("audit.jsonl");
        byte[] key = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk".getBytes(StandardCharsets.UTF_8);
        try (FileAuditSink sink = FileAuditSink.builder(file).hmacKey(key).build()) {
            sink.write(rec("a"));
        }
        assertTrue(new AuditChain(key).verify(Collections.singletonList(file)).isIntact());
        assertFalse(new AuditChain("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".getBytes(StandardCharsets.UTF_8)).verify(Collections.singletonList(file)).isIntact());
        assertFalse(new AuditChain(null).verify(Collections.singletonList(file)).isIntact());
        assertThrows(IllegalArgumentException.class, () -> new AuditChain(new byte[4]));
        assertThrows(IllegalArgumentException.class,
                () -> FileAuditSink.builder(dir.resolve("c.log")).format(AuditFormat.CEF).hashChain(true).build());
    }

    @Test
    void cliAuditVerify() throws IOException {
        Path file = dir.resolve("audit.jsonl");
        try (FileAuditSink sink = FileAuditSink.builder(file).hashChain(true).build()) {
            sink.write(rec("a"));
            sink.write(rec("b"));
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(out, true, "UTF-8");
        assertEquals(0, SecureCli.run(new String[] {"audit", "verify", file.toString()}, ps, ps));
        assertTrue(out.toString("UTF-8").contains("2 record(s), chain intact"));
        Files.write(file, new String(Files.readAllBytes(file), StandardCharsets.UTF_8).replace("\"a\"", "\"z\"").getBytes(StandardCharsets.UTF_8));
        out.reset();
        assertEquals(1, SecureCli.run(new String[] {"audit", "verify", file.toString()}, ps, ps));
        assertTrue(out.toString("UTF-8").contains("TAMPERED: audit.jsonl:1"));
        assertEquals(2, SecureCli.run(new String[] {"audit"}, ps, ps));
        assertEquals(2, SecureCli.run(new String[] {"audit", "verify", file.toString(), "--key-env", "SECURE_TEST_UNSET_VAR"}, ps, ps));
    }

    @Test
    void syslogOverUdpIsRfc5424WithCef() throws Exception {
        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(5000);
            try (SyslogAuditSink sink = SyslogAuditSink.builder("127.0.0.1", server.getLocalPort()).appName("orders api").hostname("web-1").build()) {
                sink.write(AuditRecord.of(SecurityEvent.builder(SecurityEvent.Type.REQUEST_BLOCKED, "i1").path("/x").build()));
            }
            DatagramPacket p = new DatagramPacket(new byte[8192], 8192);
            server.receive(p);
            String msg = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
            assertTrue(msg.matches("^<108>1 \\d{4}-\\d\\d-\\d\\dT[\\d:.]+Z web-1 orders_api - REQUEST_BLOCKED - CEF:0\\|wahindra\\|secure\\|1\\|REQUEST_BLOCKED\\|.*"), msg);
        }
    }

    @Test
    void syslogOverTcpUsesOctetCountingAndReconnects() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(5000);
            try (SyslogAuditSink sink = SyslogAuditSink.builder("127.0.0.1", server.getLocalPort())
                    .protocol(SyslogAuditSink.Protocol.TCP).format(AuditFormat.JSON).build()) {
                sink.write(rec("one"));
                Socket first = server.accept();
                String got = readFrame(first.getInputStream());
                assertTrue(got.contains("\"event\":\"one\""), got);
                first.close();
                // The first write after the server closed may still succeed (buffered) or fail; keep
                // writing until the sink reconnects.
                Socket second = null;
                for (int i = 0; i < 20 && second == null; i++) {
                    try {
                        sink.write(rec("two"));
                    } catch (IOException expected) {
                        continue;
                    }
                    server.setSoTimeout(200);
                    try {
                        second = server.accept();
                    } catch (java.net.SocketTimeoutException notYet) {
                        Thread.sleep(50);
                    }
                }
                assertNotNull(second, "reconnected");
                assertTrue(readFrame(second.getInputStream()).contains("\"event\":\"two\""));
                second.close();
            }
        }
    }

    /**
     * TLS: a server whose certificate the client trusts gets the message; with the default trust
     * store (which does not know this self-signed certificate) the handshake fails, so nothing is sent.
     * The certificate is created for this test only, with the JDK's keytool.
     */
    @Test
    void syslogOverTlsVerifiesTheServerCertificate() throws Exception {
        Path ks = dir.resolve("server.p12");
        char[] pw = "test-only-keystore".toCharArray();
        String keytool = Paths.get(System.getProperty("java.home"), "bin", isWindows() ? "keytool.exe" : "keytool").toString();
        if (!Files.exists(Paths.get(keytool))) {
            keytool = Paths.get(System.getProperty("java.home"), "..", "bin", isWindows() ? "keytool.exe" : "keytool").toString();
        }
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "syslog", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=localhost", "-ext", "SAN=ip:127.0.0.1,dns:localhost",
                "-storetype", "PKCS12", "-keystore", ks.toString(), "-storepass", new String(pw), "-keypass", new String(pw))
                .redirectErrorStream(true).start();
        assertTrue(p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0, "keytool failed");

        java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) {
            store.load(in, pw);
        }
        javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, pw);
        javax.net.ssl.SSLContext serverCtx = javax.net.ssl.SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        javax.net.ssl.SSLContext clientCtx = javax.net.ssl.SSLContext.getInstance("TLS");
        clientCtx.init(null, tmf.getTrustManagers(), null);

        try (javax.net.ssl.SSLServerSocket server = (javax.net.ssl.SSLServerSocket) serverCtx.getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(10000);
            List<String> got = Collections.synchronizedList(new ArrayList<String>());
            Thread acceptor = new Thread(() -> {
                for (int i = 0; i < 2; i++) {
                    try (Socket s = server.accept()) {
                        got.add(readFrame(s.getInputStream()));
                    } catch (IOException ignored) {
                        // the untrusted client aborts its handshake
                    }
                }
            });
            acceptor.start();

            try (SyslogAuditSink untrusting = SyslogAuditSink.builder("127.0.0.1", server.getLocalPort())
                    .protocol(SyslogAuditSink.Protocol.TLS).build()) {
                assertThrows(IOException.class, () -> untrusting.write(rec("must-not-arrive")));
            }
            try (SyslogAuditSink trusting = SyslogAuditSink.builder("127.0.0.1", server.getLocalPort())
                    .protocol(SyslogAuditSink.Protocol.TLS).format(AuditFormat.JSON)
                    .sslSocketFactory(clientCtx.getSocketFactory()).build()) {
                trusting.write(rec("over-tls"));
                // Stay connected until the server has read it (TLS 1.3 sends a session ticket after
                // the handshake; closing at once would make the server's read fail).
                acceptor.join(15000);
            }
            assertEquals(1, got.size(), got.toString());
            assertTrue(got.get(0).contains("\"event\":\"over-tls\""), got.get(0));
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }

    /** Reads one octet-counted frame: "LEN SP MSG". */
    private static String readFrame(InputStream in) throws IOException {
        StringBuilder len = new StringBuilder();
        int c;
        while ((c = in.read()) != ' ') {
            if (c < 0) {
                throw new IOException("closed");
            }
            len.append((char) c);
        }
        byte[] msg = new byte[Integer.parseInt(len.toString())];
        int off = 0;
        while (off < msg.length) {
            int n = in.read(msg, off, msg.length - off);
            if (n < 0) {
                throw new IOException("short frame");
            }
            off += n;
        }
        return new String(msg, StandardCharsets.UTF_8);
    }

    @Test
    void auditLogNeverBlocksOrThrows() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean fail = new AtomicBoolean(true);
        List<String> written = Collections.synchronizedList(new ArrayList<String>());
        AuditSink slowFlaky = record -> {
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (fail.get()) {
                throw new IOException("disk full");
            }
            written.add(record.getEvent());
        };
        AuditLog audit = AuditLog.builder().sink(slowFlaky).queueCapacity(3).closeOnShutdown(false).build();
        long start = System.nanoTime();
        for (int i = 0; i < 50; i++) {
            audit.record(rec("e" + i));
        }
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1), "recording must not wait for the sink");
        assertTrue(audit.droppedCount() >= 46, "queue of 3 plus one in flight: " + audit.droppedCount());
        release.countDown();
        assertTrue(audit.flush(Duration.ofSeconds(5)));
        assertTrue(audit.failedWriteCount() >= 1);
        fail.set(false);
        assertTrue(audit.record(rec("after")));
        assertTrue(audit.flush(Duration.ofSeconds(5)));
        assertEquals(Collections.singletonList("after"), written);
        audit.close();
        assertFalse(audit.record(rec("late")));
        assertThrows(IllegalArgumentException.class, () -> AuditLog.builder().build());
    }

    @Test
    void auditLogAsListenerRecordsLoginsAndApplicationEvents() throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog audit = AuditLog.builder().sink(FileAuditSink.builder(file).hashChain(true).build()).closeOnShutdown(false).build();
        LoginAttemptLimiter limiter = new LoginAttemptLimiter(2, Duration.ofMinutes(15), Duration.ofMinutes(15), 1000, java.time.Clock.systemUTC())
                .onLockout(audit).onAttempt(audit);
        limiter.recordFailure("bob");
        limiter.recordFailure("bob");
        limiter.recordSuccess("alice");
        audit.onEvent(SecurityEvent.builder(SecurityEvent.Type.ACCESS_DENIED, "i").principalId("mallory").path("/api/orders/1").build());
        audit.record("order.refund", "alice", "order/42", AuditRecord.Outcome.SUCCESS);
        audit.close();
        List<String> events = new ArrayList<String>();
        for (String l : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            events.add(l.replaceAll(".*\"event\":\"([^\"]+)\".*", "$1"));
        }
        assertEquals(Arrays.asList("LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_LOCKED", "LOGIN_SUCCEEDED", "ACCESS_DENIED", "order.refund"), events);
        assertTrue(new AuditChain(null).verify(Collections.singletonList(file)).isIntact());
    }
}
