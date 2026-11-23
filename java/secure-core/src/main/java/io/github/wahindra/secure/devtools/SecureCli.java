package io.github.wahindra.secure.devtools;

import io.github.wahindra.secure.InputInspector;
import io.github.wahindra.secure.detect.DetectionResult;
import io.github.wahindra.secure.detect.Finding;
import io.github.wahindra.secure.detect.NormalizedInput;
import io.github.wahindra.secure.detect.Severity;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Developer command line, the jar's Main-Class:
 *
 * <pre>
 * java -jar secure-core.jar scan src/               # find vulnerable code (exit 1 on HIGH findings)
 * java -jar secure-core.jar check "1;SELECT pg_sleep(5)--"
 * java -jar secure-core.jar probe "http://localhost:8080/api/orders?id=FUZZ"
 * java -jar secure-core.jar rules
 * </pre>
 */
public final class SecureCli {

    private SecureCli() {
    }

    public static void main(String[] args) {
        int code;
        try {
            code = run(args, System.out, System.err);
        } catch (IOException e) {
            System.err.println("error: " + e.getMessage());
            code = 2;
        }
        System.exit(code);
    }

    /** Runs a command and returns the process exit code (0 ok, 1 findings, 2 usage error). */
    public static int run(String[] args, PrintStream out, PrintStream err) throws IOException {
        try {
            return dispatch(args, out, err);
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            return 2;
        }
    }

    private static int dispatch(String[] args, PrintStream out, PrintStream err) throws IOException {
        if (args.length == 0 || "help".equals(args[0]) || "--help".equals(args[0]) || "-h".equals(args[0])) {
            out.print(USAGE);
            return args.length == 0 ? 2 : 0;
        }
        String cmd = args[0];
        List<String> rest = new ArrayList<String>();
        for (int i = 1; i < args.length; i++) {
            rest.add(args[i]);
        }
        if ("scan".equals(cmd)) {
            return scan(rest, out);
        }
        if ("check".equals(cmd)) {
            return check(rest, out);
        }
        if ("probe".equals(cmd)) {
            return probe(rest, out);
        }
        if ("rules".equals(cmd)) {
            for (ScanRule r : ScanRule.defaults()) {
                out.printf("%-28s %-6s %-9s %-22s %s%n", r.getId(), r.getSeverity(), r.getOwasp().id2025(),
                        r.getLangs().toString().toLowerCase(Locale.ROOT), r.getMessage());
            }
            return 0;
        }
        err.println("unknown command: " + cmd);
        err.print(USAGE);
        return 2;
    }

    private static int scan(List<String> args, PrintStream out) throws IOException {
        Severity failOn = Severity.HIGH;
        boolean failNever = false;
        String format = "text";
        String output = null;
        boolean noFix = false;
        Set<String> excluded = new HashSet<String>(SourceScanner.DEFAULT_EXCLUDED_DIRS);
        List<Path> paths = new ArrayList<Path>();
        for (int i = 0; i < args.size(); i++) {
            String a = args.get(i);
            if ("--fail-on".equals(a)) {
                String v = value(args, ++i, a).toUpperCase(Locale.ROOT);
                if ("NONE".equals(v)) {
                    failNever = true;
                } else {
                    failOn = Severity.valueOf(v);
                }
            } else if ("--format".equals(a)) {
                format = value(args, ++i, a);
            } else if ("--output".equals(a) || "-o".equals(a)) {
                output = value(args, ++i, a);
            } else if ("--exclude".equals(a)) {
                excluded.add(value(args, ++i, a));
            } else if ("--no-fix".equals(a)) {
                noFix = true;
            } else if (a.startsWith("-")) {
                throw new IllegalArgumentException("unknown option " + a);
            } else {
                paths.add(Paths.get(a));
            }
        }
        if (paths.isEmpty()) {
            paths.add(Paths.get("."));
        }
        ScanReport report = new SourceScanner(ScanRule.defaults(), excluded).scan(paths.toArray(new Path[0]));
        Path base = Paths.get(".");
        String rendered;
        if ("json".equals(format)) {
            rendered = report.toJson(base);
        } else if ("sarif".equals(format)) {
            rendered = report.toSarif(base);
        } else if ("text".equals(format)) {
            rendered = report.toText(base, !noFix);
        } else {
            throw new IllegalArgumentException("--format must be text, json or sarif");
        }
        if (output != null) {
            Files.write(Paths.get(output), rendered.getBytes(StandardCharsets.UTF_8));
            out.println("wrote " + output + ": " + report.getFindings().size() + " finding(s)");
        } else {
            out.print(rendered);
            if (!rendered.endsWith("\n")) {
                out.println();
            }
        }
        return !failNever && !report.atLeast(failOn).isEmpty() ? 1 : 0;
    }

    private static int check(List<String> args, PrintStream out) {
        if (args.isEmpty()) {
            throw new IllegalArgumentException("usage: check \"<value>\" [\"<value>\"...]");
        }
        boolean anyMalicious = false;
        for (String value : args) {
            NormalizedInput n = NormalizedInput.of(value);
            DetectionResult r = InputInspector.defaults().inspect(value);
            out.println("input     : " + printable(value));
            if (!n.decoded().equals(value)) {
                out.println("decoded   : " + printable(n.decoded()));
            }
            if (!n.stripped().equals(n.decoded())) {
                out.println("stripped  : " + printable(n.stripped()));
            }
            out.println("verdict   : " + (r.isMalicious() ? "MALICIOUS (would be blocked)"
                    : r.isSuspicious() ? "suspicious (logged in monitor mode, not blocked)" : "clean")
                    + "  score=" + r.getScore() + " (block at " + DetectionResult.MALICIOUS_SCORE + ")");
            for (Finding f : r.getFindings()) {
                out.printf("  %-6s %-28s %s  [%s]%n", f.getSeverity(), f.getRuleId(), f.getDescription(),
                        f.getCategory().id2025());
            }
            out.println();
            anyMalicious |= r.isMalicious();
        }
        return anyMalicious ? 1 : 0;
    }

    private static int probe(List<String> args, PrintStream out) throws IOException {
        AttackProbe.Target target = null;
        for (int i = 0; i < args.size(); i++) {
            String a = args.get(i);
            if (target == null && !a.startsWith("-")) {
                target = new AttackProbe.Target(a);
                continue;
            }
            if (target == null) {
                throw new IllegalArgumentException("the target URL must come first");
            }
            if ("--method".equals(a) || "-X".equals(a)) {
                target.method(value(args, ++i, a));
            } else if ("--data".equals(a) || "-d".equals(a)) {
                target.body(value(args, ++i, a));
                if ("GET".equals(target.method)) {
                    target.method("POST");
                }
            } else if ("--header".equals(a) || "-H".equals(a)) {
                String h = value(args, ++i, a);
                int colon = h.indexOf(':');
                if (colon <= 0) {
                    throw new IllegalArgumentException("--header expects 'Name: value'");
                }
                target.header(h.substring(0, colon).trim(), h.substring(colon + 1).trim());
            } else if ("--baseline".equals(a)) {
                target.baseline(value(args, ++i, a));
            } else if ("--only".equals(a)) {
                for (String c : value(args, ++i, a).split(",")) {
                    target.only(c.trim());
                }
            } else if ("--allow-remote".equals(a)) {
                target.allowRemote(true);
            } else if ("--timeout".equals(a)) {
                target.timeoutMillis(Integer.parseInt(value(args, ++i, a)) * 1000);
            } else {
                throw new IllegalArgumentException("unknown option " + a);
            }
        }
        if (target == null) {
            throw new IllegalArgumentException("usage: probe \"http://localhost:8080/path?param=FUZZ\" [options]");
        }
        List<AttackProbe.Result> results = AttackProbe.run(target, out);
        int high = 0;
        int medium = 0;
        int blocked = 0;
        for (AttackProbe.Result r : results) {
            if (r.getSeverity() == Severity.HIGH) {
                high++;
            } else if (r.getSeverity() == Severity.MEDIUM) {
                medium++;
            }
            if (r.getVerdict().startsWith("blocked")) {
                blocked++;
            }
        }
        out.printf("%n%d payloads sent: %d HIGH, %d MEDIUM, %d blocked by the secure filter.%n", results.size(), high, medium, blocked);
        if (high + medium > 0) {
            out.println("Fix the code paths above (see README: How to use), then probe again.");
        }
        return high + medium > 0 ? 1 : 0;
    }

    private static String value(List<String> args, int i, String option) {
        if (i >= args.size()) {
            throw new IllegalArgumentException(option + " needs a value");
        }
        return args.get(i);
    }

    private static String printable(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length() && i < 300; i++) {
            char c = s.charAt(i);
            sb.append(c < 0x20 ? String.format("\\x%02x", (int) c) : String.valueOf(c));
        }
        return s.length() > 300 ? sb + "..." : sb.toString();
    }

    private static final String USAGE =
            "secure: developer tools for the secure library\n"
                    + "\n"
                    + "  scan [paths...]           Find vulnerable code patterns (default path: .)\n"
                    + "      --fail-on high|medium|low|none   exit 1 when findings at this level exist (default high)\n"
                    + "      --format text|json|sarif         text is clickable path:line:col in IDE terminals\n"
                    + "      --output FILE                    write the report to FILE\n"
                    + "      --exclude DIR                    skip a directory name (repeatable)\n"
                    + "      --no-fix                         omit fix hints in text output\n"
                    + "  check \"<value>\" ...       Show how the request filter sees a value and which rules match\n"
                    + "  probe <url-with-FUZZ>     Send attack payloads to YOUR local app and report what got through\n"
                    + "      -X, --method METHOD              default GET (POST when --data is given)\n"
                    + "      -d, --data BODY                  form or JSON body containing FUZZ\n"
                    + "      -H, --header 'Name: value'       extra header (repeatable; may contain FUZZ)\n"
                    + "      --only sqli,xss,path,cmd,ssti    limit the checks\n"
                    + "      --baseline VALUE                 benign value for the baseline request (default 1)\n"
                    + "      --timeout SECONDS                per request (default 15)\n"
                    + "      --allow-remote                   allow non-local targets you are authorized to test\n"
                    + "  rules                     List the scan rules\n"
                    + "\n"
                    + "Exit codes: 0 ok, 1 findings, 2 usage error.\n";
}
