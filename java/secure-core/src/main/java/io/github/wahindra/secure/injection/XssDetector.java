package io.github.wahindra.secure.injection;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.detect.Rule;
import io.github.wahindra.secure.detect.Rule.View;
import io.github.wahindra.secure.detect.RuleBasedDetector;
import io.github.wahindra.secure.detect.Severity;

import static io.github.wahindra.secure.detect.Rule.anyOf;

import java.util.ArrayList;
import java.util.List;

/**
 * Signature detector for cross-site scripting probes. Prevention is contextual output
 * encoding ({@link Encode}) plus a Content-Security-Policy; this detector is for monitoring.
 */
public final class XssDetector extends RuleBasedDetector {

    private static final OwaspCategory C = OwaspCategory.INJECTION;
    private static final XssDetector DEFAULT = new XssDetector(defaultRules());

    public XssDetector(List<Rule> rules) {
        super(rules);
    }

    public static XssDetector defaults() {
        return DEFAULT;
    }

    public static List<Rule> defaultRules() {
        List<Rule> r = new ArrayList<Rule>();
        r.add(new Rule("XSS_SCRIPT_TAG", C, Severity.HIGH, View.DECODED,
                "<\\s*/?\\s*script\\b", "<script> tag",
                anyOf("script"), anyOf("<")));
        r.add(new Rule("XSS_EVENT_HANDLER", C, Severity.HIGH, View.DECODED,
                // [^<>] stops at the next tag, so each '<' is scanned at most once: linear, not quadratic.
                "<[a-z!/][^<>]{0,1000}?[\\s/\"'`]on[a-z]{3,}\\s*=", "Inline event handler inside a tag (onerror=, onload=)",
                anyOf("<"), anyOf("on"), anyOf("=")));
        r.add(new Rule("XSS_JS_URI", C, Severity.HIGH, View.COMPACT,
                "(?:javascript|vbscript|livescript):|data:text/html|data:[a-z/+-]*;base64,", "Script-capable URI scheme",
                anyOf("script:", "data:")));
        r.add(new Rule("XSS_DANGEROUS_TAG", C, Severity.HIGH, View.DECODED,
                "<\\s*(?:iframe|frame|object|embed|applet|base|meta|link|svg|math|template|form|isindex)\\b",
                "Tag that can load or run content",
                anyOf("<")));
        r.add(new Rule("XSS_ATTRIBUTE", C, Severity.MEDIUM, View.DECODED,
                "\\b(?:srcdoc|formaction|xlink:href|style)\\s*=", "Attribute that can carry script",
                anyOf("srcdoc", "formaction", "xlink:href", "style")));
        r.add(new Rule("XSS_CSS_EXPRESSION", C, Severity.MEDIUM, View.COMPACT,
                "expression\\(|-moz-binding|behavior:url\\(", "Legacy CSS script execution",
                anyOf("expression(", "-moz-binding", "behavior:")));
        r.add(new Rule("XSS_DOM_SINK", C, Severity.MEDIUM, View.COMPACT,
                "document\\.(?:cookie|domain|write)|window\\.location|\\.innerhtml=|\\beval\\(|settimeout\\(['\"`]"
                        + "|string\\.fromcharcode\\(|\\balert\\(|\\bprompt\\(|\\bconfirm\\(",
                "DOM sink or classic probe call",
                anyOf("document.", "window.location", ".innerhtml", "eval(", "settimeout(", "fromcharcode(", "alert(", "prompt(", "confirm(")));
        r.add(new Rule("XSS_TEMPLATE_INJECTION", C, Severity.MEDIUM, View.COMPACT,
                "\\{\\{[^}]{0,200}?(?:constructor|\\$on|\\$eval|alert|prototype)[^}]{0,200}?\\}\\}", "Client-side template injection",
                anyOf("{{"), anyOf("constructor", "$on", "$eval", "alert", "prototype")));
        return r;
    }
}
