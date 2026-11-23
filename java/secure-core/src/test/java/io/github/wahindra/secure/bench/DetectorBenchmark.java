package io.github.wahindra.secure.bench;

import io.github.wahindra.secure.InputInspector;
import io.github.wahindra.secure.access.RouteAccessPolicy;
import io.github.wahindra.secure.access.SimplePrincipal;
import io.github.wahindra.secure.crypto.PasswordHasher;
import io.github.wahindra.secure.injection.Encode;
import io.github.wahindra.secure.injection.SqlInjectionDetector;
import io.github.wahindra.secure.path.PathTraversalGuard;
import io.github.wahindra.secure.web.HttpRequestInspector;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Dependency-free micro-benchmark (JMH is not required). Each case warms up, then runs
 * {@value #ROUNDS} timed rounds and reports the median time per operation.
 *
 * <pre>
 * mvn -pl secure-core test-compile
 * java -cp secure-core/target/classes:secure-core/target/test-classes io.github.wahindra.secure.bench.DetectorBenchmark
 * </pre>
 */
public final class DetectorBenchmark {

    private static final int ROUNDS = 7;
    private static final long ROUND_NANOS = 300_000_000L;
    private static long sink;

    interface Op {
        Object run() throws Exception;
    }

    public static void main(String[] args) throws Exception {
        InputInspector inspector = InputInspector.defaults();
        SqlInjectionDetector sqli = SqlInjectionDetector.defaults();

        String benign4k = repeat("The quick brown fox jumps over the lazy dog, then orders 3 items. ", 4096);
        String benign64k = repeat("The quick brown fox jumps over the lazy dog, then orders 3 items. ", 65536);

        HttpRequestInspector http = new HttpRequestInspector();
        Map<String, String[]> params = new LinkedHashMap<String, String[]>();
        for (int i = 0; i < 10; i++) {
            params.put("field" + i, new String[] {"value number " + i});
        }
        params.put("email", new String[] {"john.smith@example.com"});
        params.put("comment", new String[] {"I'll be there (maybe) -- Ann"});
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36");
        headers.put("Referer", "https://shop.example.com/cart?step=2");
        headers.put("Accept", "text/html");

        Path base = Files.createTempDirectory("bench");
        PathTraversalGuard guard = PathTraversalGuard.forBaseDirectory(base);
        RouteAccessPolicy policy = RouteAccessPolicy.builder()
                .permitAll("GET", "/public/**")
                .hasAnyRole("*", "/admin/**", "ADMIN")
                .authenticated("*", "/api/**")
                .build();
        SimplePrincipal user = SimplePrincipal.builder("alice").roles("USER").build();
        String html1k = repeat("<b>Tom & \"Jerry\"</b> ", 1024);

        System.out.printf(Locale.ROOT, "java %s, %s %s, %d cpus%n", System.getProperty("java.version"),
                System.getProperty("os.name"), System.getProperty("os.arch"), Runtime.getRuntime().availableProcessors());
        System.out.println("| Case | Median | Ops/s |");
        System.out.println("|---|---:|---:|");

        bench("inspect: short benign value (22 chars)", () -> inspector.inspect("john.smith@example.com"));
        bench("inspect: benign sentence (61 chars)", () -> inspector.inspect("Please select an option or two and we will execute the plan"));
        bench("inspect: SQLi payload (pg_sleep stacked)", () -> inspector.inspect("1;SELECT pg_sleep(5)--"));
        bench("inspect: double-encoded SQLi", () -> inspector.inspect("%2527%2520OR%25201%253D1--"));
        bench("inspect: PG DO block RAISE EXCEPTION", () -> inspector.inspect("1';DO $$BEGIN RAISE EXCEPTION '%', (SELECT version()); END$$;--"));
        bench("inspect: 4 KB benign text", () -> inspector.inspect(benign4k));
        bench("inspect: 64 KB benign text (max inspected)", () -> inspector.inspect(benign64k));
        bench("sqli only: SQLi payload", () -> sqli.inspect("' OR 1=1--"));
        bench("http: request with 12 params + 3 headers", () -> http.inspect("/api/orders/42", params, headers));

        // Adversarial input aimed at regex backtracking; must stay linear.
        bench("ReDoS probe: 64 KB of single quotes", () -> inspector.inspect(repeat("'", 65536)));
        bench("ReDoS probe: 64 KB of 'or 1=' repeated", () -> inspector.inspect(repeat("or 1=", 65536)));
        bench("ReDoS probe: 64 KB of '<a ' repeated", () -> inspector.inspect(repeat("<a ", 65536)));
        bench("ReDoS probe: 64 KB of '/*' repeated", () -> inspector.inspect(repeat("/*", 65536)));
        bench("ReDoS probe: 64 KB of '${' repeated", () -> inspector.inspect(repeat("${", 65536)));
        bench("ReDoS probe: 64 KB of '%25' repeated", () -> inspector.inspect(repeat("%25", 65536)));

        bench("PathTraversalGuard.resolve (3 segments)", () -> guard.resolve("reports/2026/q1.pdf"));
        bench("RouteAccessPolicy.evaluate", () -> policy.evaluate("GET", "/api/orders/42", user));
        bench("Encode.forHtml (1 KB)", () -> Encode.forHtml(html1k));
        PasswordHasher hasher = new PasswordHasher();
        bench("PasswordHasher.hash (600k iterations)", () -> hasher.hash("correct horse battery".toCharArray()));

        if (sink == 42) {
            System.out.println();
        }
    }

    private static void bench(String name, Op op) throws Exception {
        // Warmup: let the JIT compile the hot path.
        long warmEnd = System.nanoTime() + 2 * ROUND_NANOS;
        while (System.nanoTime() < warmEnd) {
            consume(op.run());
        }
        double[] perOp = new double[ROUNDS];
        for (int r = 0; r < ROUNDS; r++) {
            long ops = 0;
            long start = System.nanoTime();
            long end = start + ROUND_NANOS;
            long now;
            do {
                consume(op.run());
                ops++;
                now = System.nanoTime();
            } while (now < end);
            perOp[r] = (double) (now - start) / ops;
        }
        Arrays.sort(perOp);
        double median = perOp[ROUNDS / 2];
        System.out.printf(Locale.ROOT, "| %s | %s | %,.0f |%n", name, format(median), 1e9 / median);
    }

    private static void consume(Object o) {
        sink += o == null ? 0 : o.hashCode();
    }

    private static String format(double nanos) {
        if (nanos >= 1_000_000) {
            return String.format(Locale.ROOT, "%.1f ms", nanos / 1_000_000);
        }
        if (nanos >= 1_000) {
            return String.format(Locale.ROOT, "%.1f us", nanos / 1_000);
        }
        return String.format(Locale.ROOT, "%.0f ns", nanos);
    }

    private static String repeat(String s, int targetLength) {
        StringBuilder sb = new StringBuilder(targetLength + s.length());
        while (sb.length() < targetLength) {
            sb.append(s);
        }
        sb.setLength(targetLength);
        return sb.toString();
    }
}
