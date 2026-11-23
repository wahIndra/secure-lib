package io.github.wahindra.secure.devtools;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.detect.Severity;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** One source-code rule from {@code scan-rules.txt} (shared with the JavaScript scanner). */
public final class ScanRule {

    /** File families the scanner knows. */
    public enum Lang { JAVA, JS, TEMPLATE, CONFIG }

    private final String id;
    private final Set<Lang> langs;
    private final Severity severity;
    private final OwaspCategory owasp;
    private final boolean maskStrings;
    private final Pattern pattern;
    private final Pattern unless;
    private final Pattern unlessFile;
    private final String message;
    private final String fix;

    private ScanRule(Map<String, String> kv) {
        this.id = require(kv, "id");
        Set<Lang> l = new LinkedHashSet<Lang>();
        for (String s : require(kv, "lang").split("\\s*,\\s*")) {
            l.add(Lang.valueOf(s.trim().toUpperCase(Locale.ROOT)));
        }
        this.langs = Collections.unmodifiableSet(l);
        this.severity = Severity.valueOf(require(kv, "severity").toUpperCase(Locale.ROOT));
        this.owasp = OwaspCategory.valueOf(require(kv, "owasp"));
        this.maskStrings = !"raw".equals(kv.get("scope"));
        int flags = kv.containsKey("flags") && kv.get("flags").contains("i") ? Pattern.CASE_INSENSITIVE : 0;
        this.pattern = Pattern.compile(require(kv, "pattern"), flags);
        this.unless = kv.containsKey("unless") ? Pattern.compile(kv.get("unless"), Pattern.CASE_INSENSITIVE) : null;
        this.unlessFile = kv.containsKey("unless-file") ? Pattern.compile(kv.get("unless-file")) : null;
        this.message = require(kv, "message");
        this.fix = require(kv, "fix");
    }

    /** Loads the bundled default rules. */
    public static List<ScanRule> defaults() {
        InputStream in = ScanRule.class.getResourceAsStream("scan-rules.txt");
        if (in == null) {
            throw new IllegalStateException("scan-rules.txt missing from the classpath");
        }
        try {
            return parse(in);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Parses the rule file format documented at the top of {@code scan-rules.txt}. */
    public static List<ScanRule> parse(InputStream in) throws IOException {
        List<ScanRule> rules = new ArrayList<ScanRule>();
        Set<String> ids = new LinkedHashSet<String>();
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        Map<String, String> block = new LinkedHashMap<String, String>();
        int lineNo = 0;
        String line;
        while (true) {
            line = r.readLine();
            lineNo++;
            boolean end = line == null || line.trim().isEmpty();
            if (end) {
                if (!block.isEmpty()) {
                    ScanRule rule;
                    try {
                        rule = new ScanRule(block);
                    } catch (RuntimeException e) {
                        throw new IOException("invalid rule ending at line " + lineNo + ": " + e.getMessage(), e);
                    }
                    if (!ids.add(rule.id)) {
                        throw new IOException("duplicate rule id " + rule.id);
                    }
                    rules.add(rule);
                    block = new LinkedHashMap<String, String>();
                }
                if (line == null) {
                    break;
                }
                continue;
            }
            if (line.startsWith("#")) {
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new IOException("line " + lineNo + ": expected 'key: value'");
            }
            block.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
        }
        return Collections.unmodifiableList(rules);
    }

    private static String require(Map<String, String> kv, String key) {
        String v = kv.get(key);
        if (v == null || v.isEmpty()) {
            throw new IllegalArgumentException("missing '" + key + "' in rule " + kv.get("id"));
        }
        return v;
    }

    boolean appliesTo(Lang lang) { return langs.contains(lang); }
    boolean masksStrings() { return maskStrings; }
    Pattern pattern() { return pattern; }
    boolean skipsLine(String line) { return unless != null && unless.matcher(line).find(); }
    boolean skipsFile(String content) { return unlessFile != null && unlessFile.matcher(content).find(); }

    public String getId() { return id; }
    public Set<Lang> getLangs() { return langs; }
    public Severity getSeverity() { return severity; }
    public OwaspCategory getOwasp() { return owasp; }
    public String getMessage() { return message; }
    public String getFix() { return fix; }

    @Override
    public String toString() {
        return id + " " + severity + " " + owasp.id2025() + " " + Arrays.toString(langs.toArray());
    }
}
