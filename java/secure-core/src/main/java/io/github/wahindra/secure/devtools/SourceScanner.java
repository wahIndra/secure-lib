package io.github.wahindra.secure.devtools;

import io.github.wahindra.secure.detect.Severity;
import io.github.wahindra.secure.devtools.ScanRule.Lang;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Line-based static scanner that flags code patterns which commonly lead to OWASP Top 10
 * vulnerabilities, and tells the developer which guard in this library fixes each one.
 *
 * <p>It is a fast, dependency-free first line of feedback while coding, not a full SAST: it
 * does not follow data flow across lines, so treat findings as "look here" and suppress
 * reviewed ones with {@code // secure-scan:ignore RULE_ID -- reason}.
 *
 * <pre>
 * // In a unit test, so `mvn test` fails before anything is packaged or deployed:
 * SourceScanner.assertNoFindings(Severity.HIGH, Paths.get("src/main"));
 * </pre>
 */
public final class SourceScanner {

    public static final Set<String> DEFAULT_EXCLUDED_DIRS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            ".git", ".svn", ".hg", ".idea", ".vscode", ".gradle", ".mvn", "node_modules", "target", "build", "dist",
            "out", "coverage", "vendor", "bower_components", ".next", ".nuxt", "test-vectors")));

    private static final long MAX_FILE_BYTES = 2L * 1024 * 1024;
    private static final Pattern IGNORE = Pattern.compile("secure-scan:ignore(?:\\s+([A-Z0-9_,\\s]+?))?(?:\\s+--|\\s*$|\\s*\\*/|\\s*-->)");

    private final List<ScanRule> rules;
    private final Set<String> excludedDirs;

    public SourceScanner(List<ScanRule> rules, Set<String> excludedDirs) {
        this.rules = Collections.unmodifiableList(new ArrayList<ScanRule>(rules));
        this.excludedDirs = Collections.unmodifiableSet(new HashSet<String>(excludedDirs));
    }

    public static SourceScanner defaults() {
        return new SourceScanner(ScanRule.defaults(), DEFAULT_EXCLUDED_DIRS);
    }

    /**
     * Fails with an {@link AssertionError} listing every finding at or above {@code minimum}.
     * Missing paths are ignored, so the same test works in modules without e.g. src/main/resources.
     */
    public static void assertNoFindings(Severity minimum, Path... paths) throws IOException {
        ScanReport report = defaults().scan(paths);
        List<ScanFinding> failing = report.atLeast(minimum);
        if (!failing.isEmpty()) {
            throw new AssertionError(failing.size() + " security finding(s) at " + minimum + " or above:\n"
                    + ScanReport.toText(failing, null, true));
        }
    }

    public ScanReport scan(Path... paths) throws IOException {
        final List<ScanFinding> findings = new ArrayList<ScanFinding>();
        final int[] files = {0};
        for (Path root : paths) {
            if (!Files.exists(root)) {
                continue;
            }
            if (Files.isRegularFile(root)) {
                files[0] += scanFile(root, findings) ? 1 : 0;
                continue;
            }
            Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    Path name = dir.getFileName();
                    return name != null && excludedDirs.contains(name.toString()) && !dir.equals(root)
                            ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (attrs.size() <= MAX_FILE_BYTES) {
                        files[0] += scanFile(file, findings) ? 1 : 0;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    return FileVisitResult.CONTINUE;
                }
            });
        }
        return new ScanReport(findings, files[0], rules.size());
    }

    /** Scans text as if it came from a file with the given name (used by tests and editors). */
    public List<ScanFinding> scanText(String fileName, String content) {
        List<ScanFinding> out = new ArrayList<ScanFinding>();
        Lang lang = langOf(fileName);
        if (lang != null) {
            scanContent(java.nio.file.Paths.get(fileName), lang, content, out);
        }
        return out;
    }

    /** Language family for a file name, or {@code null} if the scanner does not handle it. */
    public static Lang langOf(String fileName) {
        String n = fileName.toLowerCase(Locale.ROOT);
        if (n.endsWith(".min.js") || n.endsWith(".d.ts") || n.endsWith(".map")) {
            return null;
        }
        if (n.endsWith(".java") || n.endsWith(".kt") || n.endsWith(".kts") || n.endsWith(".groovy") || n.endsWith(".scala")) {
            return Lang.JAVA;
        }
        if (n.endsWith(".js") || n.endsWith(".mjs") || n.endsWith(".cjs") || n.endsWith(".ts") || n.endsWith(".mts")
                || n.endsWith(".cts") || n.endsWith(".jsx") || n.endsWith(".tsx")) {
            return Lang.JS;
        }
        if (n.endsWith(".html") || n.endsWith(".htm") || n.endsWith(".jsp") || n.endsWith(".jspx") || n.endsWith(".vue")
                || n.endsWith(".svelte") || n.endsWith(".ftl") || n.endsWith(".hbs") || n.endsWith(".handlebars")
                || n.endsWith(".ejs") || n.endsWith(".njk") || n.endsWith(".twig") || n.endsWith(".thymeleaf")) {
            return Lang.TEMPLATE;
        }
        String base = n.substring(Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\')) + 1);
        if (n.endsWith(".properties") || n.endsWith(".yml") || n.endsWith(".yaml") || base.equals(".env")
                || base.startsWith(".env.") || n.endsWith(".conf")) {
            return Lang.CONFIG;
        }
        return null;
    }

    private boolean scanFile(Path file, List<ScanFinding> out) throws IOException {
        Path name = file.getFileName();
        Lang lang = name == null ? null : langOf(name.toString());
        if (lang == null) {
            return false;
        }
        byte[] bytes = Files.readAllBytes(file);
        scanContent(file, lang, new String(bytes, StandardCharsets.UTF_8), out);
        return true;
    }

    private void scanContent(Path file, Lang lang, String content, List<ScanFinding> out) {
        List<ScanRule> applicable = new ArrayList<ScanRule>();
        for (ScanRule r : rules) {
            if (r.appliesTo(lang) && !r.skipsFile(content)) {
                applicable.add(r);
            }
        }
        if (applicable.isEmpty()) {
            return;
        }
        String[] lines = content.split("\r?\n", -1);
        boolean inBlockComment = false;
        for (int i = 0; i < lines.length; i++) {
            String raw = lines[i];
            String trimmed = raw.trim();
            // Whole-line comments are skipped so documentation examples do not raise findings.
            if (inBlockComment) {
                if (trimmed.contains("*/")) {
                    inBlockComment = false;
                }
                continue;
            }
            if (isCommentLine(trimmed, lang)) {
                if (trimmed.startsWith("/*") && !trimmed.contains("*/")) {
                    inBlockComment = true;
                }
                continue;
            }
            String masked = maskStrings(raw, lang);
            // Only Java/JS have // comments; in config and templates "//" is usually part of a URL.
            int commentAt = lang == Lang.JAVA || lang == Lang.JS ? masked.indexOf("//") : -1;
            String code = commentAt >= 0 ? raw.substring(0, commentAt) : raw;
            String maskedCode = commentAt >= 0 ? masked.substring(0, commentAt) : masked;
            Set<String> ignored = ignoredRules(raw, i > 0 ? lines[i - 1] : null, lang);
            for (ScanRule rule : applicable) {
                if (ignored != null && (ignored.isEmpty() || ignored.contains(rule.getId()))) {
                    continue;
                }
                Matcher m = rule.pattern().matcher(rule.masksStrings() ? maskedCode : code);
                if (m.find() && !rule.skipsLine(code)) {
                    String src = trimmed.length() > 200 ? trimmed.substring(0, 200) + "..." : trimmed;
                    out.add(new ScanFinding(rule, file, i + 1, m.start() + 1, src));
                }
            }
        }
    }

    private static boolean isCommentLine(String t, Lang lang) {
        if (lang == Lang.CONFIG) {
            return t.startsWith("#") || t.startsWith("!") || t.startsWith(";");
        }
        if (lang == Lang.TEMPLATE) {
            return t.startsWith("<!--") || t.startsWith("<%--") || t.startsWith("{{!--");
        }
        return t.startsWith("//") || t.startsWith("/*") || t.startsWith("*");
    }

    /** {@code null} = nothing suppressed, empty = everything suppressed, otherwise the listed ids. */
    private static Set<String> ignoredRules(String line, String previous, Lang lang) {
        Set<String> result = null;
        // The marker counts on the flagged line itself, or on a comment-only line directly above it.
        String above = previous != null && isCommentLine(previous.trim(), lang) ? previous : null;
        for (String l : new String[] {line, above}) {
            if (l == null || !l.contains("secure-scan:ignore")) {
                continue;
            }
            Matcher m = IGNORE.matcher(l);
            if (!m.find()) {
                continue;
            }
            if (m.group(1) == null || m.group(1).trim().isEmpty()) {
                return Collections.emptySet();
            }
            if (result == null) {
                result = new HashSet<String>();
            }
            for (String id : m.group(1).split("[,\\s]+")) {
                if (!id.isEmpty()) {
                    result.add(id);
                }
            }
        }
        return result;
    }

    /**
     * Replaces the contents of string literals with 'x' (quotes kept) so rules about code do not
     * fire on text such as {@code "eval("}. Length and column positions are preserved.
     */
    static String maskStrings(String line, Lang lang) {
        if (lang == Lang.CONFIG || lang == Lang.TEMPLATE) {
            return line;
        }
        StringBuilder sb = new StringBuilder(line.length());
        char quote = 0;
        int interpolation = 0; // brace depth inside a JS template literal's ${...}
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (interpolation > 0) {
                // ${...} is code, not text: keep it visible to the rules.
                if (c == '{') {
                    interpolation++;
                } else if (c == '}') {
                    interpolation--;
                }
                sb.append(c);
            } else if (quote == '`' && c == '$' && i + 1 < line.length() && line.charAt(i + 1) == '{') {
                interpolation = 1;
                sb.append("${");
                i++;
            } else if (quote == 0) {
                if (c == '"' || c == '\'' || (c == '`' && lang == Lang.JS)) {
                    quote = c;
                } else if (c == '/' && i + 1 < line.length() && line.charAt(i + 1) == '/') {
                    sb.append(line.substring(i));
                    return sb.toString();
                }
                sb.append(c);
            } else if (c == '\\' && i + 1 < line.length()) {
                sb.append("xx");
                i++;
            } else if (c == quote) {
                quote = 0;
                sb.append(c);
            } else {
                sb.append('x');
            }
        }
        return sb.toString();
    }

    public List<ScanRule> getRules() {
        return rules;
    }
}
