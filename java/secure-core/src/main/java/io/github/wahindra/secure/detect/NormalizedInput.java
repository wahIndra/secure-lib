package io.github.wahindra.secure.detect;

import java.util.regex.Pattern;

/**
 * Pre-computed views of one raw input, shared by all detectors so decoding runs once.
 */
public final class NormalizedInput {

    /** Inputs longer than this are only inspected up to the limit. */
    public static final int MAX_INSPECTED_LENGTH = 64 * 1024;

    // MySQL executes the body of /*!50000 ... */, so only the markers are removed.
    private static final Pattern EXECUTABLE_COMMENT_OPEN = Pattern.compile("/\\*!\\d*");
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?(\\*/|$)", Pattern.DOTALL);
    private static final Pattern STRAY_COMMENT_CLOSE = Pattern.compile("\\*/");
    private static final Pattern SPACES = Pattern.compile(" {2,}");

    private final String raw;
    private final String decoded;
    private String stripped;
    private String compact;

    private NormalizedInput(String raw) {
        this.raw = raw;
        String limited = raw.length() > MAX_INSPECTED_LENGTH ? raw.substring(0, MAX_INSPECTED_LENGTH) : raw;
        this.decoded = InputNormalizer.normalize(limited);
    }

    public static NormalizedInput of(String raw) {
        return new NormalizedInput(raw == null ? "" : raw);
    }

    public String raw() { return raw; }

    public String decoded() { return decoded; }

    public String stripped() {
        if (stripped == null) {
            String s = decoded;
            boolean changed = false;
            if (s.contains("/*") || s.contains("*/")) {
                s = EXECUTABLE_COMMENT_OPEN.matcher(s).replaceAll(" ");
                s = BLOCK_COMMENT.matcher(s).replaceAll(" ");
                s = STRAY_COMMENT_CLOSE.matcher(s).replaceAll(" ");
                changed = true;
            }
            if (s.indexOf('+') >= 0) {
                s = s.replace('+', ' ');
                changed = true;
            }
            stripped = changed ? SPACES.matcher(s).replaceAll(" ") : s;
        }
        return stripped;
    }

    public String compact() {
        if (compact == null) {
            StringBuilder sb = new StringBuilder(stripped().length());
            String s = stripped();
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c != ' ' && c != '\0') {
                    sb.append(c);
                }
            }
            compact = sb.toString();
        }
        return compact;
    }

    public String view(Rule.View view) {
        switch (view) {
            case STRIPPED: return stripped();
            case COMPACT: return compact();
            default: return decoded;
        }
    }
}
