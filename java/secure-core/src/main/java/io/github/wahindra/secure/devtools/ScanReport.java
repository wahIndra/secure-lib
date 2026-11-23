package io.github.wahindra.secure.devtools;

import io.github.wahindra.secure.detect.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Result of a scan, with text (IDE-clickable), JSON and SARIF 2.1.0 renderings. */
public final class ScanReport {

    private final List<ScanFinding> findings;
    private final int filesScanned;
    private final int ruleCount;

    ScanReport(List<ScanFinding> findings, int filesScanned, int ruleCount) {
        List<ScanFinding> sorted = new ArrayList<ScanFinding>(findings);
        Collections.sort(sorted, new Comparator<ScanFinding>() {
            @Override
            public int compare(ScanFinding a, ScanFinding b) {
                int c = b.getRule().getSeverity().compareTo(a.getRule().getSeverity());
                if (c == 0) {
                    c = a.getFile().toString().compareTo(b.getFile().toString());
                }
                return c != 0 ? c : Integer.compare(a.getLine(), b.getLine());
            }
        });
        this.findings = Collections.unmodifiableList(sorted);
        this.filesScanned = filesScanned;
        this.ruleCount = ruleCount;
    }

    public List<ScanFinding> getFindings() { return findings; }
    public int getFilesScanned() { return filesScanned; }

    public List<ScanFinding> atLeast(Severity minimum) {
        List<ScanFinding> out = new ArrayList<ScanFinding>();
        for (ScanFinding f : findings) {
            if (f.getRule().getSeverity().compareTo(minimum) >= 0) {
                out.add(f);
            }
        }
        return out;
    }

    public int count(Severity s) {
        int n = 0;
        for (ScanFinding f : findings) {
            if (f.getRule().getSeverity() == s) {
                n++;
            }
        }
        return n;
    }

    /** {@code path:line:col SEVERITY RULE message}, the format IntelliJ, VS Code and most terminals turn into links. */
    public String toText(Path baseDir, boolean withFix) {
        StringBuilder sb = new StringBuilder(toText(findings, baseDir, withFix));
        sb.append(findings.isEmpty() ? "No findings" : findings.size() + " finding(s)")
                .append(" (").append(count(Severity.HIGH)).append(" HIGH, ").append(count(Severity.MEDIUM))
                .append(" MEDIUM, ").append(count(Severity.LOW)).append(" LOW) in ").append(filesScanned)
                .append(" file(s), ").append(ruleCount).append(" rules.\n");
        return sb.toString();
    }

    static String toText(List<ScanFinding> findings, Path baseDir, boolean withFix) {
        StringBuilder sb = new StringBuilder();
        for (ScanFinding f : findings) {
            ScanRule r = f.getRule();
            sb.append(display(f.getFile(), baseDir)).append(':').append(f.getLine()).append(':').append(f.getColumn())
                    .append(": ").append(r.getSeverity()).append(' ').append(r.getId()).append(" [")
                    .append(r.getOwasp().id2025()).append(' ').append(r.getOwasp().title()).append("] ")
                    .append(r.getMessage()).append('\n')
                    .append("    ").append(f.getSource()).append('\n');
            if (withFix) {
                sb.append("    fix: ").append(r.getFix()).append('\n');
            }
        }
        return sb.toString();
    }

    public String toJson(Path baseDir) {
        StringBuilder sb = new StringBuilder("{\"filesScanned\":").append(filesScanned).append(",\"findings\":[");
        for (int i = 0; i < findings.size(); i++) {
            ScanFinding f = findings.get(i);
            ScanRule r = f.getRule();
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"rule\":").append(json(r.getId()))
                    .append(",\"severity\":").append(json(r.getSeverity().name()))
                    .append(",\"owasp\":").append(json(r.getOwasp().id2025()))
                    .append(",\"category\":").append(json(r.getOwasp().title()))
                    .append(",\"file\":").append(json(display(f.getFile(), baseDir)))
                    .append(",\"line\":").append(f.getLine())
                    .append(",\"column\":").append(f.getColumn())
                    .append(",\"message\":").append(json(r.getMessage()))
                    .append(",\"fix\":").append(json(r.getFix()))
                    .append(",\"source\":").append(json(f.getSource())).append('}');
        }
        return sb.append("]}").toString();
    }

    /** SARIF 2.1.0, readable by the VS Code SARIF Viewer, IntelliJ (Qodana) and GitHub code scanning. */
    public String toSarif(Path baseDir) {
        Map<String, ScanRule> used = new LinkedHashMap<String, ScanRule>();
        for (ScanFinding f : findings) {
            used.put(f.getRule().getId(), f.getRule());
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{")
                .append("\"tool\":{\"driver\":{\"name\":\"secure-scan\",\"informationUri\":\"https://github.com/wahIndra/secure-lib\",\"rules\":[");
        int i = 0;
        for (ScanRule r : used.values()) {
            if (i++ > 0) {
                sb.append(',');
            }
            sb.append("{\"id\":").append(json(r.getId()))
                    .append(",\"shortDescription\":{\"text\":").append(json(r.getMessage())).append('}')
                    .append(",\"help\":{\"text\":").append(json(r.getFix())).append('}')
                    .append(",\"properties\":{\"tags\":[\"security\",").append(json(r.getOwasp().id2025())).append("]}")
                    .append(",\"defaultConfiguration\":{\"level\":").append(json(level(r.getSeverity()))).append("}}");
        }
        sb.append("]}},\"results\":[");
        for (int j = 0; j < findings.size(); j++) {
            ScanFinding f = findings.get(j);
            if (j > 0) {
                sb.append(',');
            }
            sb.append("{\"ruleId\":").append(json(f.getRule().getId()))
                    .append(",\"level\":").append(json(level(f.getRule().getSeverity())))
                    .append(",\"message\":{\"text\":").append(json(f.getRule().getMessage() + ". Fix: " + f.getRule().getFix())).append('}')
                    .append(",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":")
                    .append(json(display(f.getFile(), baseDir).replace('\\', '/'))).append("},\"region\":{\"startLine\":")
                    .append(f.getLine()).append(",\"startColumn\":").append(f.getColumn()).append("}}}]}");
        }
        return sb.append("]}]}").toString();
    }

    private static String level(Severity s) {
        return s == Severity.HIGH ? "error" : s == Severity.MEDIUM ? "warning" : "note";
    }

    private static String display(Path file, Path baseDir) {
        if (baseDir != null) {
            try {
                Path abs = file.toAbsolutePath().normalize();
                Path base = baseDir.toAbsolutePath().normalize();
                if (abs.startsWith(base)) {
                    return base.relativize(abs).toString();
                }
            } catch (IllegalArgumentException ignored) {
                // different roots on Windows: fall through to the original path
            }
        }
        return file.toString();
    }

    static String json(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c == ' ' || c == ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }
}
