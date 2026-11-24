package io.github.wahindra.secure.devtools;

import io.github.wahindra.secure.detect.Severity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Manual broken-object-level-authorization (IDOR / BOLA) check: requests one object as its owner,
 * then as a different user and with no credentials, and reports when anyone but the owner gets it.
 *
 * <p>Credentials are plain headers, so it works with any login: bearer tokens from Keycloak,
 * Auth0, Entra ID, Okta or Cognito, session cookies, or API keys.
 *
 * <pre>
 * secure idor http://localhost:8080/api/orders/42 \
 *   --as-owner "Authorization: Bearer $TOKEN_A" --as-other "Authorization: Bearer $TOKEN_B"
 * </pre>
 *
 * Only loopback and private-network targets are allowed unless {@code allowRemote} is set.
 */
public final class IdorProbe {

    /** One request with fixed credentials. */
    public static final class Target {
        final String url;
        String method = "GET";
        String body;
        final Map<String, String> owner = new LinkedHashMap<String, String>();
        final Map<String, String> other = new LinkedHashMap<String, String>();
        String marker;
        boolean anonymous = true;
        boolean allowRemote;
        int timeoutMillis = 15000;

        public Target(String url) { this.url = url; }
        public Target method(String m) { method = m.toUpperCase(java.util.Locale.ROOT); return this; }
        public Target body(String b) { body = b; return this; }
        /** A header that authenticates the object's owner, e.g. {@code Authorization: Bearer ...}. */
        public Target ownerHeader(String name, String value) { owner.put(name, value); return this; }
        /** A header that authenticates a different, ordinary user. */
        public Target otherHeader(String name, String value) { other.put(name, value); return this; }
        /** Text that only the owner's data contains (an email, order number...). Makes detection exact. */
        public Target marker(String text) { marker = text; return this; }
        /** Also try without any credentials (default on). */
        public Target anonymous(boolean v) { anonymous = v; return this; }
        public Target allowRemote(boolean v) { allowRemote = v; return this; }
        public Target timeoutMillis(int ms) { timeoutMillis = ms; return this; }
    }

    /** Outcome for one identity. */
    public static final class Result {
        final String as;
        final int status;
        final Severity severity;
        final String verdict;

        Result(String as, int status, Severity severity, String verdict) {
            this.as = as;
            this.status = status;
            this.severity = severity;
            this.verdict = verdict;
        }

        public String getAs() { return as; }
        public int getStatus() { return status; }
        /** {@code null} when access was correctly refused. */
        public Severity getSeverity() { return severity; }
        public String getVerdict() { return verdict; }
        public boolean isVulnerable() { return severity != null; }
    }

    private IdorProbe() {
    }

    public static List<Result> run(Target t) throws IOException {
        if (t.owner.isEmpty() || t.other.isEmpty()) {
            throw new IllegalArgumentException("give the owner's and another user's credentials (--as-owner / --as-other)");
        }
        AttackProbe.checkHostAllowed(t.url, t.allowRemote);

        List<Result> results = new ArrayList<Result>();
        Http owner = send(t, t.owner);
        if (owner.error != null || owner.status < 200 || owner.status >= 300) {
            throw new IOException("the owner's request did not succeed (" + (owner.error != null ? owner.error : "HTTP " + owner.status)
                    + "); check the URL and the owner's credentials first");
        }
        if (t.marker != null && !owner.body.contains(t.marker)) {
            throw new IOException("the owner's response does not contain the marker text; pick text that is in it");
        }
        results.add(new Result("owner", owner.status, null, "allowed, as expected"));
        results.add(judge("other user", send(t, t.other), owner, t.marker));
        if (t.anonymous) {
            results.add(judge("no credentials", send(t, Collections.<String, String>emptyMap()), owner, t.marker));
        }
        return Collections.unmodifiableList(results);
    }

    private static Result judge(String as, Http r, Http owner, String marker) {
        if (r.error != null) {
            return new Result(as, 0, null, "request failed: " + r.error);
        }
        if (r.status == 401 || r.status == 403 || r.status == 404) {
            return new Result(as, r.status, null, "refused (HTTP " + r.status + "), as expected");
        }
        if (r.status >= 300 && r.status < 400) {
            return new Result(as, r.status, null, "redirected (HTTP " + r.status + "), probably to a login page");
        }
        if (r.status < 200 || r.status >= 300) {
            return new Result(as, r.status, Severity.LOW, "unexpected HTTP " + r.status + "; check the server log");
        }
        boolean leaked = marker != null ? r.body.contains(marker) : r.body.equals(owner.body);
        if (leaked) {
            return new Result(as, r.status, Severity.HIGH, (marker != null ? "response contains the owner's marker" : "same response as the owner")
                    + ": broken object level authorization (IDOR). Check ownership with AccessGuard, or query by owner id from the token");
        }
        if (marker != null) {
            return new Result(as, r.status, null, "HTTP " + r.status + " without the owner's data (probably this user's own data)");
        }
        return new Result(as, r.status, Severity.MEDIUM, "HTTP " + r.status + " with a different body; check by hand, or rerun with --marker "
                + "set to text only the owner's data contains");
    }

    private static final class Http {
        int status;
        String body = "";
        String error;
    }

    private static Http send(Target t, Map<String, String> headers) {
        Http r = new Http();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(t.url).openConnection();
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(t.timeoutMillis);
            c.setReadTimeout(t.timeoutMillis);
            c.setRequestMethod(t.method);
            c.setRequestProperty("User-Agent", "secure-idor/0.1");
            for (Map.Entry<String, String> h : headers.entrySet()) {
                c.setRequestProperty(h.getKey(), h.getValue());
            }
            if (t.body != null) {
                if (!headers.containsKey("Content-Type")) {
                    c.setRequestProperty("Content-Type", t.body.trim().startsWith("{") ? "application/json" : "application/x-www-form-urlencoded");
                }
                c.setDoOutput(true);
                OutputStream out = c.getOutputStream();
                out.write(t.body.getBytes(StandardCharsets.UTF_8));
                out.close();
            }
            r.status = c.getResponseCode();
            InputStream in = r.status >= 400 ? c.getErrorStream() : c.getInputStream();
            if (in != null) {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] b = new byte[8192];
                int n;
                while ((n = in.read(b)) > 0 && buf.size() < 2 * 1024 * 1024) {
                    buf.write(b, 0, n);
                }
                in.close();
                r.body = new String(buf.toByteArray(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            r.error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            if (c != null) {
                c.disconnect();
            }
        }
        return r;
    }
}
