package io.github.wahindra.secure.detect;

import io.github.wahindra.secure.OwaspCategory;

import java.util.regex.Pattern;

/** A regex rule evaluated against one of the {@link NormalizedInput} views. */
public final class Rule {

    public enum View {
        /** Fully decoded, lower-cased, whitespace collapsed. Comments intact. */
        DECODED,
        /** {@link #DECODED} with SQL comments and '+' turned into spaces. */
        STRIPPED,
        /** {@link #STRIPPED} with all whitespace removed. Catches "pg_sl eep(" style splitting. */
        COMPACT
    }

    private final String id;
    private final OwaspCategory category;
    private final Severity severity;
    private final View view;
    private final Pattern pattern;
    private final String description;
    private final String[][] required;

    /**
     * @param required literal prefilter: for every group, at least one of its strings must occur
     *                 in the view before the regex runs. Must only list text the regex cannot match
     *                 without. A substring scan is far cheaper than a regex tried at every position.
     */
    public Rule(String id, OwaspCategory category, Severity severity, View view, String regex, String description,
                String[]... required) {
        this.id = id;
        this.category = category;
        this.severity = severity;
        this.view = view;
        this.pattern = Pattern.compile(regex, Pattern.DOTALL);
        this.description = description;
        this.required = required;
    }

    /** Shorthand for one prefilter group. */
    public static String[] anyOf(String... literals) {
        return literals;
    }

    public boolean matches(NormalizedInput input) {
        String text = input.view(view);
        for (String[] group : required) {
            if (!containsAny(text, group)) {
                return false;
            }
        }
        return pattern.matcher(text).find();
    }

    private static boolean containsAny(String text, String[] literals) {
        for (String literal : literals) {
            if (text.contains(literal)) {
                return true;
            }
        }
        return false;
    }

    public Finding toFinding() {
        return new Finding(id, category, severity, description);
    }

    public String getId() { return id; }
}
