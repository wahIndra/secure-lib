package io.github.wahindra.secure.path;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.detect.Rule;
import io.github.wahindra.secure.detect.Rule.View;
import io.github.wahindra.secure.detect.RuleBasedDetector;
import io.github.wahindra.secure.detect.Severity;

import static io.github.wahindra.secure.detect.Rule.anyOf;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects directory traversal and local file inclusion probes in any input. To actually
 * open files safely use {@link PathTraversalGuard}.
 */
public final class PathTraversalDetector extends RuleBasedDetector {

    private static final OwaspCategory C = OwaspCategory.BROKEN_ACCESS_CONTROL;
    private static final PathTraversalDetector DEFAULT = new PathTraversalDetector(defaultRules());

    public PathTraversalDetector(List<Rule> rules) {
        super(rules);
    }

    public static PathTraversalDetector defaults() {
        return DEFAULT;
    }

    public static List<Rule> defaultRules() {
        List<Rule> r = new ArrayList<Rule>();
        r.add(new Rule("PATH_DOT_DOT", C, Severity.HIGH, View.DECODED,
                "(?:^|[\\\\/])\\.{2,}(?:[\\\\/]|$)", "../ traversal segment (after decoding)",
                anyOf("..")));
        r.add(new Rule("PATH_NULL_BYTE", C, Severity.HIGH, View.DECODED,
                "\\x00", "Null byte (extension truncation)",
                anyOf("\0")));
        r.add(new Rule("PATH_SENSITIVE_FILE", C, Severity.HIGH, View.DECODED,
                "(?:^|[\\\\/])(?:etc[\\\\/](?:passwd|shadow|group|hosts|sudoers)|proc[\\\\/](?:self|\\d+)[\\\\/]"
                        + "|windows[\\\\/](?:win\\.ini|system32)|boot\\.ini|web-inf[\\\\/]|meta-inf[\\\\/]"
                        + "|\\.ssh[\\\\/]|\\.aws[\\\\/]credentials|\\.git[\\\\/](?:config|head)|\\.env(?:$|\\.))",
                "Well-known sensitive file",
                anyOf("etc", "proc", "windows", "boot.ini", "web-inf", "meta-inf", ".ssh", ".aws", ".git", ".env")));
        r.add(new Rule("PATH_WRAPPER", C, Severity.HIGH, View.COMPACT,
                "^(?:file|php|zip|phar|jar|expect|glob|data|netdoc|gopher)://|^php:filter", "Stream wrapper / URL scheme as path",
                anyOf("://", "php:")));
        r.add(new Rule("PATH_ABSOLUTE", C, Severity.MEDIUM, View.DECODED,
                "^(?:/|\\\\\\\\|[a-z]:[\\\\/])", "Absolute or UNC path"));
        r.add(new Rule("PATH_DOT_DOT_DOUBLE", C, Severity.HIGH, View.DECODED,
                "\\.\\.\\.\\.[\\\\/]{1,2}|\\.\\.[\\\\/]{2}|\\.\\.;/", "Filter evasion (....// or ..;/)",
                anyOf("..")));
        return r;
    }
}
