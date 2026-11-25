package io.github.wahindra.secure.audit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Sends records to a syslog server or SIEM collector as RFC 5424 messages, over UDP, TCP or TLS
 * (RFC 5425; octet-counting framing on TCP and TLS). The record itself, CEF by default, is the
 * message text.
 *
 * <pre>
 * SyslogAuditSink.builder("siem.example.com", 6514).protocol(SyslogAuditSink.Protocol.TLS).build();
 * </pre>
 *
 * <p>TLS verifies the server's certificate and host name. On a failed send the connection is
 * dropped and opened again for the next record; the failed record is counted, not retried.
 */
public final class SyslogAuditSink implements AuditSink {

    public enum Protocol { UDP, TCP, TLS }

    private final String host;
    private final int port;
    private final Protocol protocol;
    private final AuditFormat format;
    private final String appName;
    private final String hostname;
    private final int facility;
    private final int connectTimeoutMillis;
    private final SSLSocketFactory sslFactory;
    private DatagramSocket udp;
    private Socket socket;
    private OutputStream out;

    private SyslogAuditSink(Builder b) {
        this.host = b.host;
        this.port = b.port;
        this.protocol = b.protocol;
        this.format = b.format;
        this.appName = printable(b.appName, 48);
        this.hostname = printable(b.hostname != null ? b.hostname : localHostname(), 255);
        this.facility = b.facility;
        this.connectTimeoutMillis = b.connectTimeoutMillis;
        this.sslFactory = b.sslFactory != null ? b.sslFactory : (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    public static Builder builder(String host, int port) {
        return new Builder(host, port);
    }

    @Override
    public synchronized void write(AuditRecord record) throws IOException {
        byte[] msg = message(record).getBytes(StandardCharsets.UTF_8);
        try {
            if (protocol == Protocol.UDP) {
                if (udp == null) {
                    udp = new DatagramSocket();
                }
                udp.send(new DatagramPacket(msg, msg.length, new InetSocketAddress(host, port)));
            } else {
                if (out == null) {
                    connect();
                }
                out.write((msg.length + " ").getBytes(StandardCharsets.US_ASCII));
                out.write(msg);
                out.flush();
            }
        } catch (IOException | RuntimeException e) {
            close();
            throw e;
        }
    }

    /** The RFC 5424 message for a record (without TCP framing). */
    String message(AuditRecord r) {
        int pri = facility * 8 + syslogSeverity(r.getSeverity());
        return "<" + pri + ">1 " + AuditFormat.timestamp(r) + " " + hostname + " " + appName + " - "
                + printable(r.getEvent(), 32) + " - " + format.format(r);
    }

    /** CEF 0..10 to syslog: 9+ critical, 7+ warning, 5+ notice, else informational. */
    static int syslogSeverity(int cef) {
        return cef >= 9 ? 2 : cef >= 7 ? 4 : cef >= 5 ? 5 : 6;
    }

    @Override
    public synchronized void close() {
        if (udp != null) {
            udp.close();
            udp = null;
        }
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // closing anyway
            }
            socket = null;
            out = null;
        }
    }

    private void connect() throws IOException {
        Socket plain = new Socket();
        try {
            plain.connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            if (protocol == Protocol.TLS) {
                SSLSocket tls = (SSLSocket) sslFactory.createSocket(plain, host, port, true);
                SSLParameters params = tls.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS"); // check the host name, not just the chain
                tls.setSSLParameters(params);
                tls.startHandshake();
                socket = tls;
            } else {
                socket = plain;
            }
            out = socket.getOutputStream();
        } catch (IOException | RuntimeException e) {
            plain.close();
            throw e;
        }
    }

    /** RFC 5424 header fields: printable US-ASCII, no spaces, length-limited, "-" if empty. */
    static String printable(String s, int max) {
        if (s == null || s.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length() && sb.length() < max; i++) {
            char c = s.charAt(i);
            sb.append(c > 32 && c < 127 ? c : '_');
        }
        return sb.toString();
    }

    private static String localHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "-";
        }
    }

    public static final class Builder {
        private final String host;
        private final int port;
        private Protocol protocol = Protocol.UDP;
        private AuditFormat format = AuditFormat.CEF;
        private String appName = "secure";
        private String hostname;
        private int facility = 13; // log audit
        private int connectTimeoutMillis = 5000;
        private SSLSocketFactory sslFactory;

        private Builder(String host, int port) {
            if (host == null || host.trim().isEmpty() || port < 1 || port > 65535) {
                throw new IllegalArgumentException("syslog host and port (1-65535) are required");
            }
            this.host = host.trim();
            this.port = port;
        }

        /** UDP (default), TCP or TLS. Prefer TLS across networks: UDP and TCP are plain text. */
        public Builder protocol(Protocol v) { protocol = v; return this; }
        /** {@link AuditFormat#CEF} (default), {@code JSON} or {@code ECS}. */
        public Builder format(AuditFormat v) { format = v; return this; }
        /** RFC 5424 APP-NAME, default {@code secure}. Set it to your application's name. */
        public Builder appName(String v) { appName = v; return this; }
        /** RFC 5424 HOSTNAME, default the local host name. */
        public Builder hostname(String v) { hostname = v; return this; }
        /** Syslog facility 0..23, default 13 (log audit). */
        public Builder facility(int v) {
            if (v < 0 || v > 23) {
                throw new IllegalArgumentException("facility must be 0..23");
            }
            facility = v;
            return this;
        }
        public Builder connectTimeoutMillis(int v) { connectTimeoutMillis = v; return this; }
        /** For TLS with a private CA: a factory built from your trust store. */
        public Builder sslSocketFactory(SSLSocketFactory v) { sslFactory = v; return this; }

        public SyslogAuditSink build() {
            return new SyslogAuditSink(this);
        }
    }
}
