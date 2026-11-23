package io.github.wahindra.secure;

import io.github.wahindra.secure.detect.DetectionResult;
import io.github.wahindra.secure.detect.ThreatDetector;
import io.github.wahindra.secure.injection.CommandInjectionDetector;
import io.github.wahindra.secure.injection.SqlInjectionDetector;
import io.github.wahindra.secure.injection.XssDetector;
import io.github.wahindra.secure.path.PathTraversalDetector;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Runs the shared files in /test-vectors; the JavaScript suite runs the same files. */
class AttackVectorTest {

    @TestFactory
    List<DynamicTest> sqlInjection() throws IOException {
        return vectors("sqli", SqlInjectionDetector.defaults());
    }

    @TestFactory
    List<DynamicTest> xss() throws IOException {
        return vectors("xss", XssDetector.defaults());
    }

    @TestFactory
    List<DynamicTest> pathTraversal() throws IOException {
        return vectors("path", PathTraversalDetector.defaults());
    }

    @TestFactory
    List<DynamicTest> commandInjection() throws IOException {
        return vectors("cmd", CommandInjectionDetector.defaults());
    }

    /** The combined inspector must not produce false positives on any benign file. */
    @TestFactory
    List<DynamicTest> combinedInspectorBenign() throws IOException {
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        for (String kind : new String[] {"sqli", "xss", "path", "cmd"}) {
            for (final String line : load(kind + "-benign.txt")) {
                tests.add(DynamicTest.dynamicTest("all/benign: " + line, () -> {
                    DetectionResult r = InputInspector.defaults().inspect(line);
                    assertFalse(r.isMalicious(), () -> "false positive: " + line + " -> " + r);
                }));
            }
        }
        return tests;
    }

    /**
     * ReDoS guard: adversarial 64 KB inputs must be inspected in linear time. Before the rules
     * were bounded, "&lt;a " repeated took about 9 seconds. The limit is deliberately generous
     * so slow CI machines do not flake.
     */
    @TestFactory
    List<DynamicTest> noCatastrophicBacktracking() {
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        for (final String unit : new String[] {"'", "or 1=", "<a ", "/*", "${", "%25", "{{", "nc ", "a/*", "'/*", "cast(", "<a on", "&#"}) {
            tests.add(DynamicTest.dynamicTest("64 KB of '" + unit + "'", () -> {
                StringBuilder sb = new StringBuilder(65536 + unit.length());
                while (sb.length() < 65536) {
                    sb.append(unit);
                }
                String input = sb.toString();
                InputInspector.defaults().inspect(input); // warm up
                long start = System.nanoTime();
                InputInspector.defaults().inspect(input);
                long millis = (System.nanoTime() - start) / 1_000_000;
                assertTrue(millis < 1000, () -> "took " + millis + " ms");
            }));
        }
        return tests;
    }

    private static List<DynamicTest> vectors(String kind, final ThreatDetector detector) throws IOException {
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        for (final String line : load(kind + "-malicious.txt")) {
            tests.add(DynamicTest.dynamicTest(kind + "/malicious: " + line, () -> {
                DetectionResult r = detector.inspect(line);
                assertTrue(r.isMalicious(), () -> "not detected: " + line + " -> " + r);
            }));
        }
        for (final String line : load(kind + "-benign.txt")) {
            tests.add(DynamicTest.dynamicTest(kind + "/benign: " + line, () -> {
                DetectionResult r = detector.inspect(line);
                assertFalse(r.isMalicious(), () -> "false positive: " + line + " -> " + r);
            }));
        }
        return tests;
    }

    static List<String> load(String file) throws IOException {
        Path dir = Paths.get(System.getProperty("vectors.dir", "../../test-vectors"));
        List<String> out = new ArrayList<String>();
        for (String line : Files.readAllLines(dir.resolve(file), StandardCharsets.UTF_8)) {
            if (!line.trim().isEmpty() && !line.startsWith("# ")) {
                out.add(line);
            }
        }
        return out;
    }
}
