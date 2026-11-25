package io.github.wahindra.secure;

import io.github.wahindra.secure.audit.AuditChain;
import io.github.wahindra.secure.audit.AuditFormat;
import io.github.wahindra.secure.audit.AuditRecord;
import io.github.wahindra.secure.web.SecurityEvent;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * test-vectors/audit-vectors.txt: audit records and their exact lines in every format, plus the
 * hash chain over them. The JavaScript suite reads the same file, so both libraries must write
 * byte-identical audit logs.
 *
 * <p>Blocks separated by blank lines; each line is {@code key TAB value}. Input values may use
 * {@code \n}, {@code \t}, {@code \\} and {@code \}{@code uXXXX}; output values ({@code json},
 * {@code ecs}, {@code cef}, {@code chained}) are literal. Regenerate the outputs after a deliberate
 * format change with {@code main} (arguments: input file, output file).
 */
final class AuditVectors {

    static final String HMAC_KEY = "audit-vector-hmac-key-0123456789";
    static final String[] OUTPUT_KEYS = {"json", "ecs", "cef", "chained", "chainedHmac"};

    static final class Case {
        final Map<String, String> values = new LinkedHashMap<String, String>();

        String in(String key) {
            String v = values.get(key);
            return v == null ? null : unescape(v);
        }

        String out(String key) {
            return values.get(key);
        }

        String name() {
            return values.get("case");
        }
    }

    private AuditVectors() {
    }

    static Path file() {
        return Paths.get(System.getProperty("vectors.dir", "../../test-vectors"), "audit-vectors.txt");
    }

    static List<Case> load(Path file) throws IOException {
        List<Case> cases = new ArrayList<Case>();
        Case current = null;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isEmpty()) {
                current = null;
                continue;
            }
            if (line.startsWith("#")) {
                continue;
            }
            int tab = line.indexOf('\t');
            if (tab < 0) {
                throw new IllegalStateException("no TAB in: " + line);
            }
            if (current == null) {
                current = new Case();
                cases.add(current);
            }
            current.values.put(line.substring(0, tab), line.substring(tab + 1));
        }
        return cases;
    }

    static AuditRecord build(Case c) {
        Instant ts = Instant.parse(c.in("timestamp"));
        if ("security".equals(c.in("kind"))) {
            SecurityEvent.Builder b = SecurityEvent.builder(SecurityEvent.Type.valueOf(c.in("event")), c.in("incidentId"))
                    .timestamp(ts).method(c.in("method")).path(c.in("path")).remoteAddress(c.in("remoteAddress"))
                    .principalId(c.in("principalId")).detail(c.in("detail"));
            if (c.in("category") != null) {
                b.category(OwaspCategory.valueOf(c.in("category")));
            }
            if (c.in("ruleIds") != null) {
                for (String r : c.in("ruleIds").split(",")) {
                    b.ruleId(r);
                }
            }
            return AuditRecord.of(b.build());
        }
        AuditRecord.Builder b = AuditRecord.builder(c.in("event")).timestamp(ts).incidentId(c.in("incidentId"))
                .principalId(c.in("principalId")).remoteAddress(c.in("remoteAddress")).method(c.in("method"))
                .path(c.in("path")).resource(c.in("resource")).detail(c.in("detail"));
        if (c.in("outcome") != null) {
            b.outcome(AuditRecord.Outcome.valueOf(c.in("outcome").toUpperCase(java.util.Locale.ROOT)));
        }
        if (c.in("severity") != null) {
            b.severity(Integer.parseInt(c.in("severity")));
        }
        return b.build();
    }

    static String unescape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char n = s.charAt(++i);
            if (n == 'n') {
                sb.append('\n');
            } else if (n == 't') {
                sb.append('\t');
            } else if (n == 'u') {
                sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                i += 4;
            } else {
                sb.append(n);
            }
        }
        return sb.toString();
    }

    /** Fills in the expected outputs: {@code main(inputFile, outputFile)}. */
    public static void main(String[] args) throws IOException {
        List<Case> cases = load(Paths.get(args[0]));
        AuditChain sha = new AuditChain(null);
        AuditChain hmac = new AuditChain(HMAC_KEY.getBytes(StandardCharsets.UTF_8));
        String prev = AuditChain.GENESIS;
        String prevHmac = AuditChain.GENESIS;
        StringBuilder out = new StringBuilder("# Generated from the Java implementation by AuditVectors.main; both test suites check it.\n"
                + "# chained / chainedHmac: the json line in a hash chain over the cases in this order\n"
                + "# (HMAC key: " + HMAC_KEY + ").\n\n");
        for (Case c : cases) {
            for (String k : OUTPUT_KEYS) {
                c.values.remove(k);
            }
            AuditRecord r = build(c);
            String json = AuditFormat.JSON.format(r);
            c.values.put("json", json);
            c.values.put("ecs", AuditFormat.ECS.format(r));
            c.values.put("cef", AuditFormat.CEF.format(r));
            String linked = sha.link(prev, json);
            prev = linked.substring(linked.length() - 66, linked.length() - 2);
            c.values.put("chained", linked);
            String linkedHmac = hmac.link(prevHmac, json);
            prevHmac = linkedHmac.substring(linkedHmac.length() - 66, linkedHmac.length() - 2);
            c.values.put("chainedHmac", linkedHmac);
            for (Map.Entry<String, String> e : c.values.entrySet()) {
                out.append(e.getKey()).append('\t').append(e.getValue()).append('\n');
            }
            out.append('\n');
        }
        Files.write(Paths.get(args[1]), out.toString().trim().concat("\n").getBytes(StandardCharsets.UTF_8));
    }
}
