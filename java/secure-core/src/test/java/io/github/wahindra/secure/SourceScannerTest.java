package io.github.wahindra.secure;

import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.ScanFinding;
import io.github.wahindra.secure.devtools.ScanReport;
import io.github.wahindra.secure.devtools.ScanRule;
import io.github.wahindra.secure.devtools.SecureCli;
import io.github.wahindra.secure.devtools.SourceScanner;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Runs the shared fixtures in test-vectors/scan; the JavaScript scanner runs the same files. */
class SourceScannerTest {

    private static final Pattern EXPECT = Pattern.compile("expect-next:\\s*([A-Z0-9_,\\s]+)");
    private static final Path DIR = Paths.get(System.getProperty("vectors.dir", "../../test-vectors"), "scan");

    @TestFactory
    List<DynamicTest> vulnerableFixturesProduceExactlyTheExpectedFindings() throws IOException {
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        for (final Path file : files(DIR.resolve("vulnerable"))) {
            tests.add(DynamicTest.dynamicTest(file.getFileName().toString(), () -> {
                Map<Integer, TreeSet<String>> expected = expectations(file);
                Map<Integer, TreeSet<String>> actual = new TreeMap<Integer, TreeSet<String>>();
                for (ScanFinding f : SourceScanner.defaults().scan(file).getFindings()) {
                    actual.computeIfAbsent(f.getLine(), k -> new TreeSet<String>()).add(f.getRule().getId());
                }
                assertEquals(expected, actual, "line -> rule ids in " + file);
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> safeFixturesProduceNoFindings() throws IOException {
        List<DynamicTest> tests = new ArrayList<DynamicTest>();
        for (final Path file : files(DIR.resolve("safe"))) {
            tests.add(DynamicTest.dynamicTest(file.getFileName().toString(), () -> {
                ScanReport r = SourceScanner.defaults().scan(file);
                assertTrue(r.getFindings().isEmpty(), () -> r.toText(null, false));
            }));
        }
        return tests;
    }

    @Test
    void everyRuleIsExercisedByAFixture() throws IOException {
        TreeSet<String> covered = new TreeSet<String>();
        for (Path file : files(DIR.resolve("vulnerable"))) {
            for (TreeSet<String> ids : expectations(file).values()) {
                covered.addAll(ids);
            }
        }
        TreeSet<String> all = new TreeSet<String>();
        for (ScanRule r : ScanRule.defaults()) {
            all.add(r.getId());
        }
        all.removeAll(covered);
        assertTrue(all.isEmpty(), "rules without a fixture line: " + all);
    }

    @Test
    void assertNoFindingsFailsTheBuildWithAReadableReport() {
        AssertionError e = assertThrows(AssertionError.class,
                () -> SourceScanner.assertNoFindings(Severity.HIGH, DIR.resolve("vulnerable")));
        assertTrue(e.getMessage().contains("SQL_STRING_CONCAT"));
        assertTrue(e.getMessage().contains("fix: "));
        assertTrue(e.getMessage().contains("OrderController.java:10:"), e.getMessage());
    }

    @Test
    void cliScanExitCodesAndFormats() throws IOException {
        assertEquals(1, cli("scan", DIR.resolve("vulnerable").toString()));
        assertEquals(0, cli("scan", DIR.resolve("safe").toString()));
        assertEquals(0, cli("scan", "--fail-on", "none", DIR.resolve("vulnerable").toString()));
        String sarif = out("scan", "--format", "sarif", "--fail-on", "none", DIR.resolve("vulnerable").toString());
        assertTrue(sarif.startsWith("{\"$schema\""));
        assertTrue(sarif.contains("\"ruleId\":\"SQL_STRING_CONCAT\""));
        String json = out("scan", "--format", "json", "--fail-on", "none", DIR.resolve("vulnerable").toString());
        assertTrue(json.contains("\"severity\":\"HIGH\""));
        assertEquals(2, cli("scan", "--format", "xml"));
    }

    @Test
    void cliCheckExplainsAPayload() throws IOException {
        String text = out("check", "%27%20OR%201%3D1--");
        assertTrue(text.contains("decoded   : ' or 1=1--"), text);
        assertTrue(text.contains("MALICIOUS"));
        assertTrue(text.contains("SQLI_BOOLEAN_TAUTOLOGY"));
        assertEquals(1, cli("check", "1;SELECT pg_sleep(5)--"));
        assertEquals(0, cli("check", "O'Brien"));
    }

    @Test
    void probeRefusesPublicTargetsAndMissingFuzz() throws IOException {
        assertTrue(err("probe", "http://93.184.215.14/?q=FUZZ").contains("only targets local/private servers"));
        assertTrue(err("probe", "http://localhost:1/?q=1").contains("put FUZZ"));
        assertEquals(2, cli("probe", "http://93.184.215.14/?q=FUZZ"));
    }

    @Test
    void scanTextDetectsLanguageFromFileName() {
        assertFalse(SourceScanner.defaults().scanText("A.java", "String s = \"SELECT * FROM t WHERE a = \" + b;").isEmpty());
        assertTrue(SourceScanner.defaults().scanText("notes.txt", "String s = \"SELECT * FROM t WHERE a = \" + b;").isEmpty());
        assertEquals(ScanRule.Lang.CONFIG, SourceScanner.langOf("config/.env.production"));
        assertEquals(ScanRule.Lang.JS, SourceScanner.langOf("src/App.tsx"));
    }

    private static Map<Integer, TreeSet<String>> expectations(Path file) throws IOException {
        Map<Integer, TreeSet<String>> expected = new TreeMap<Integer, TreeSet<String>>();
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            Matcher m = EXPECT.matcher(lines.get(i));
            if (m.find()) {
                TreeSet<String> ids = new TreeSet<String>();
                for (String id : m.group(1).split("[,\\s]+")) {
                    if (!id.isEmpty()) {
                        ids.add(id);
                    }
                }
                expected.put(i + 2, ids);
            }
        }
        return expected;
    }

    private static List<Path> files(Path dir) throws IOException {
        List<Path> out = new ArrayList<Path>();
        try (DirectoryStream<Path> s = Files.newDirectoryStream(dir)) {
            for (Path p : s) {
                out.add(p);
            }
        }
        java.util.Collections.sort(out);
        return out;
    }

    private static int cli(String... args) throws IOException {
        return SecureCli.run(args, new PrintStream(new ByteArrayOutputStream()), new PrintStream(new ByteArrayOutputStream()));
    }

    private static String err(String... args) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        SecureCli.run(args, new PrintStream(new ByteArrayOutputStream()), new PrintStream(buf, true, "UTF-8"));
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String out(String... args) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        SecureCli.run(args, new PrintStream(buf, true, "UTF-8"), new PrintStream(new ByteArrayOutputStream()));
        return new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }
}
