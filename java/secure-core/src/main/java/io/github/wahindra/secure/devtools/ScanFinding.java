package io.github.wahindra.secure.devtools;

import java.nio.file.Path;

/** One match of a {@link ScanRule} in a source file. */
public final class ScanFinding {

    private final ScanRule rule;
    private final Path file;
    private final int line;
    private final int column;
    private final String source;

    ScanFinding(ScanRule rule, Path file, int line, int column, String source) {
        this.rule = rule;
        this.file = file;
        this.line = line;
        this.column = column;
        this.source = source;
    }

    public ScanRule getRule() { return rule; }
    public Path getFile() { return file; }
    /** 1-based. */
    public int getLine() { return line; }
    /** 1-based. */
    public int getColumn() { return column; }
    /** The offending line, trimmed and capped at 200 characters. */
    public String getSource() { return source; }

    @Override
    public String toString() {
        return file + ":" + line + ":" + column + " " + rule.getSeverity() + " " + rule.getId();
    }
}
