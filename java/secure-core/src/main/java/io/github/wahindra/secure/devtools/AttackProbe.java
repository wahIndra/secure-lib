package io.github.wahindra.secure.devtools;

import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.ssrf.UrlGuard;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Manual "try to break it" check for a developer's own running app: replaces {@code FUZZ} in a
 * URL, form body, JSON body or header with each payload from {@code probe-payloads.txt} and
 * reports responses that show the attack worked (database errors, delays, reflected markup,
 * file contents, command output, template evaluation, leaked stack traces).
 *
 * <p>By default only loopback and private-network targets are allowed, because this sends real
 * attack payloads. Only point it at systems you own or are authorized to test.
 */
public final class AttackProbe {

    /** One request template: where FUZZ goes. */
    public static final class Target {
        String url;
        String method = "GET";
        String body;
        Map<String, String> headers = new LinkedHashMap<String, String>();
        String baseline = "1";
        Set<String> only = new LinkedHashSet<String>();
        boolean allowRemote;
        int timeoutMillis = 15000;

        public Target(String url) { this.url = url; }
        public Target method(String m) { method = m.toUpperCase(java.util.Locale.ROOT); return this; }
        public Target body(String b) { body = b; return this; }
        public Target header(String name, String value) { headers.put(name, value); return this; }
        public Target baseline(String value) { baseline = value; return this; }
        public Target only(String check) { only.add(check); return this; }
        public Target allowRemote(boolean v) { allowRemote = v; return this; }
        public Target timeoutMillis(int ms) { timeoutMillis = ms; return this; }
    }

    /** Outcome for one payload. */
    public static final class Result {
        final String check;
        final String payload;
        final int status;
        final long millis;
        final Severity severity;
        final String verdict;

        Result(String check, String payload, int status, long millis, Severity severity, String verdict) {
            this.check = check;
            this.payload = payload;
            this.status = status;
            this.millis = millis;
            this.severity = severity;
            this.verdict = verdict;
        }

        public String getCheck() { return check; }
        public String getPayload() { return payload; }
        public int getStatus() { return status; }
        public long getMillis() { return millis; }
        /** {@code null} when nothing was found. */
        public Severity getSeverity() { return severity; }
        public String getVerdict() { return verdict; }
        public boolean isVulnerable() { return severity != null; }
    }

    private static final class Response {
        int status;
        String body = "";
        long millis;
        String error;
    }

    static final Pattern DB_ERROR = Pattern.compile(
            "syntax error at or near|unterminated quoted string|PSQLException|org\\.postgresql|SQLSyntaxErrorException"
                    + "|SQLException|You have an error in your SQL syntax|mysql_fetch|ORA-\\d{5}|SQLITE_ERROR|sqlite3\\."
                    + "|Unclosed quotation mark|Incorrect syntax near|org\\.hibernate|JDBCException|QueryFailedError"
                    // "ERROR: secprobe" is how PostgreSQL reports the RAISE EXCEPTION payload; the bare
                    // word is not enough because a safe page may echo the (encoded) payload back.
                    + "|SequelizeDatabaseError|invalid input syntax for|ERROR:\\s+invalid input|ERROR:\\s+secprobe",
            Pattern.CASE_INSENSITIVE);
    static final Pattern PASSWD = Pattern.compile("root:[x*!]?:0:0:|\\[fonts\\]|for 16-bit app support");
    static final Pattern ID_OUTPUT = Pattern.compile("uid=\\d+\\([^)]*\\)\\s+gid=\\d+");
    static final Pattern STACK_TRACE = Pattern.compile(
            "\\bat [\\w$.]+\\([\\w$]+\\.java:\\d+\\)|Exception in thread|java\\.lang\\.\\w+Exception|"
                    + "\\n\\s+at .+\\(.+\\.(?:js|ts):\\d+:\\d+\\)|Traceback \\(most recent call last\\)");
    private static final long DELAY_THRESHOLD_MS = 2500;

    private AttackProbe() {
    }

    /** Loads the bundled payloads as (check, payload) pairs. */
    public static List<String[]> payloads() {
        List<String[]> out = new ArrayList<String[]>();
        InputStream in = AttackProbe.class.getResourceAsStream("probe-payloads.txt");
        if (in == null) {
            throw new IllegalStateException("probe-payloads.txt missing from the classpath");
        }
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = r.readLine()) != null) {
                int tab = line.indexOf('\t');
                if (!line.startsWith("#") && tab > 0) {
                    out.add(new String[] {line.substring(0, tab), line.substring(tab + 1)});
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    /** Refuses targets outside loopback/private networks unless {@code allowRemote} is set. */
    public static void checkTargetAllowed(Target t) throws IOException {
        if (!t.url.contains("FUZZ") && (t.body == null || !t.body.contains("FUZZ")) && !t.headers.toString().contains("FUZZ")) {
            throw new IllegalArgumentException("put FUZZ where the payload should go (URL, --data or --header)");
        }
        checkHostAllowed(t.url.replace("FUZZ", "1"), t.allowRemote);
    }

    /** Refuses non-http(s) URLs, and hosts outside loopback/private networks unless {@code allowRemote}. */
    static void checkHostAllowed(String url, boolean allowRemote) throws IOException {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("not a valid URL: " + url);
        }
        if (uri.getHost() == null || !("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("target must be an http(s) URL");
        }
        if (allowRemote) {
            return;
        }
        for (InetAddress a : InetAddress.getAllByName(uri.getHost())) {
            if (!UrlGuard.isBlockedAddress(a)) {
                throw new IllegalArgumentException(uri.getHost() + " resolves to public address " + a.getHostAddress()
                        + ". The probe only targets local/private servers by default; pass --allow-remote only for"
                        + " systems you own or are authorized to test.");
            }
        }
    }

    public static List<Result> run(Target t, java.io.PrintStream progress) throws IOException {
        checkTargetAllowed(t);
        Response base1 = send(t, t.baseline);
        Response base2 = send(t, t.baseline);
        if (base1.error != null) {
            throw new IOException("baseline request failed: " + base1.error);
        }
        long baseMillis = Math.max(base1.millis, base2.millis);
        boolean baseHasMarker = base1.body.contains("94011");
        boolean baseHasDbError = DB_ERROR.matcher(base1.body).find();
        if (progress != null) {
            progress.printf("baseline: HTTP %d, %d bytes, %d ms%n", base1.status, base1.body.length(), baseMillis);
        }

        List<Result> results = new ArrayList<Result>();
        Response pendingTrue = null;
        String pendingTruePayload = null;
        for (String[] p : payloads()) {
            String check = p[0];
            String payload = p[1];
            String family = check.startsWith("sqli") ? "sqli" : check.startsWith("cmd") ? "cmd" : check;
            if (!t.only.isEmpty() && !t.only.contains(family) && !t.only.contains(check)) {
                continue;
            }
            Response r = send(t, payload);
            Severity sev = null;
            String verdict;
            if (r.error != null) {
                verdict = "request failed: " + r.error;
            } else if (r.body.contains("request_rejected")) {
                verdict = "blocked by secure filter (HTTP " + r.status + ")";
            } else {
                verdict = "no sign of vulnerability";
                boolean delayed = r.millis - baseMillis >= DELAY_THRESHOLD_MS;
                if (check.equals("sqli-error") && !baseHasDbError && DB_ERROR.matcher(r.body.replace(payload, "")).find()) {
                    sev = Severity.HIGH;
                    verdict = "database error in response: SQL injection likely";
                } else if ((check.equals("sqli-time") || check.equals("cmd-time")) && delayed) {
                    sev = Severity.HIGH;
                    verdict = "response delayed " + (r.millis - baseMillis) + " ms: "
                            + (check.equals("cmd-time") ? "command" : "time-based SQL") + " injection likely";
                } else if (check.equals("xss") && r.body.contains(payload)) {
                    sev = Severity.HIGH;
                    verdict = "payload reflected unencoded: XSS";
                } else if (check.equals("path") && PASSWD.matcher(r.body).find()) {
                    sev = Severity.HIGH;
                    verdict = "system file content returned: path traversal";
                } else if (check.equals("cmd") && ID_OUTPUT.matcher(r.body).find()) {
                    sev = Severity.HIGH;
                    verdict = "command output in response: command injection";
                } else if (check.equals("ssti") && !baseHasMarker && r.body.contains("94011")) {
                    sev = Severity.HIGH;
                    verdict = "expression evaluated (31337*3=94011): template injection";
                } else if (check.equals("sqli-true")) {
                    pendingTrue = r;
                    pendingTruePayload = payload;
                } else if (check.equals("sqli-false") && pendingTrue != null) {
                    if (differs(pendingTrue, r) && differs(r, base1) && !differs(pendingTrue, base1)) {
                        sev = Severity.MEDIUM;
                        verdict = "response changes with the injected condition (" + pendingTruePayload + " vs this): boolean-based SQL injection possible";
                    }
                    pendingTrue = null;
                }
                if (sev == null && r.status >= 500 && STACK_TRACE.matcher(r.body).find()) {
                    sev = Severity.MEDIUM;
                    verdict = "HTTP " + r.status + " with stack trace in body: unhandled error leaks details (A10)";
                } else if (sev == null && r.status >= 500) {
                    sev = Severity.LOW;
                    verdict = "HTTP " + r.status + ": input causes a server error; check the logs";
                }
            }
            Result res = new Result(check, payload, r.status, r.millis, sev, verdict);
            results.add(res);
            if (progress != null) {
                progress.printf("%-7s %-10s HTTP %3d %6d ms  %-46s %s%n", sev == null ? "ok" : sev.name(), check, r.status,
                        r.millis, truncate(payload, 46), verdict);
            }
        }
        return Collections.unmodifiableList(results);
    }

    private static boolean differs(Response a, Response b) {
        if (a.status != b.status) {
            return true;
        }
        int diff = Math.abs(a.body.length() - b.body.length());
        return diff > Math.max(50, Math.max(a.body.length(), b.body.length()) / 10);
    }

    private static Response send(Target t, String payload) {
        Response r = new Response();
        long start = System.nanoTime();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(t.url.replace("FUZZ", urlEncode(payload))).openConnection();
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(t.timeoutMillis);
            c.setReadTimeout(t.timeoutMillis);
            c.setRequestMethod(t.method);
            c.setRequestProperty("User-Agent", "secure-probe/0.1");
            for (Map.Entry<String, String> h : t.headers.entrySet()) {
                c.setRequestProperty(h.getKey(), h.getValue().replace("FUZZ", payload));
            }
            if (t.body != null) {
                boolean json = t.body.trim().startsWith("{") || t.body.trim().startsWith("[");
                String b = t.body.replace("FUZZ", json ? jsonEscape(payload) : urlEncode(payload));
                if (!t.headers.containsKey("Content-Type")) {
                    c.setRequestProperty("Content-Type", json ? "application/json" : "application/x-www-form-urlencoded");
                }
                c.setDoOutput(true);
                OutputStream out = c.getOutputStream();
                out.write(b.getBytes(StandardCharsets.UTF_8));
                out.close();
            }
            r.status = c.getResponseCode();
            InputStream in = r.status >= 400 ? c.getErrorStream() : c.getInputStream();
            r.body = in == null ? "" : read(in);
        } catch (IOException e) {
            r.error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            r.millis = (System.nanoTime() - start) / 1_000_000;
            if (c != null) {
                c.disconnect();
            }
        }
        return r;
    }

    private static String read(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] b = new byte[8192];
        int n;
        while ((n = in.read(b)) > 0 && buf.size() < 2 * 1024 * 1024) {
            buf.write(b, 0, n);
        }
        in.close();
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String jsonEscape(String s) {
        String q = ScanReport.json(s);
        return q.substring(1, q.length() - 1);
    }

    private static String truncate(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n - 3) + "...";
    }
}
