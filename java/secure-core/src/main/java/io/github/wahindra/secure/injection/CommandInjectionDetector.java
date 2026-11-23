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
 * Detects OS command injection, JNDI lookups (Log4Shell) and expression-language injection.
 * Prevention: never pass user input through a shell; use {@link SafeCommand}.
 */
public final class CommandInjectionDetector extends RuleBasedDetector {

    private static final OwaspCategory C = OwaspCategory.INJECTION;
    private static final String COMMANDS =
            "(?:sh|bash|zsh|dash|ksh|csh|nc|ncat|netcat|socat|telnet|curl|wget|python[0-9.]*|perl|ruby|php|"
                    + "powershell|pwsh|cmd(?:\\.exe)?|certutil|bitsadmin|whoami|id|uname|cat|ls|dir|ping|nslookup|"
                    + "rm|chmod|chown|mkfifo|base64|env|type|net|ifconfig|ipconfig)";

    private static final CommandInjectionDetector DEFAULT = new CommandInjectionDetector(defaultRules());

    public CommandInjectionDetector(List<Rule> rules) {
        super(rules);
    }

    public static CommandInjectionDetector defaults() {
        return DEFAULT;
    }

    public static List<Rule> defaultRules() {
        List<Rule> r = new ArrayList<Rule>();
        r.add(new Rule("CMD_SUBSTITUTION", C, Severity.HIGH, View.DECODED,
                "\\$\\([^)]{1,200}\\)|\\$\\{ifs\\}|\\$ifs\\$", "Shell command substitution $(...) or $IFS",
                anyOf("$(", "${ifs}", "$ifs$")));
        r.add(new Rule("CMD_BACKTICK", C, Severity.MEDIUM, View.DECODED,
                "`[^`]{1,200}`", "Backtick command substitution",
                anyOf("`")));
        r.add(new Rule("CMD_CHAINED", C, Severity.HIGH, View.DECODED,
                "(?:[;&|`\\n]|&&|\\|\\|)\\s*" + COMMANDS
                        + "(?:\\s+-{1,2}[a-z]|\\s+/|\\s+(?:https?|ftp)://|\\s*$|\\s*[;|&#]|\\s+[a-z0-9.:/-]+\\s*[|;&])",
                "Shell separator followed by a command",
                anyOf(";", "&", "|", "`")));
        r.add(new Rule("CMD_PIPE_TO_SHELL", C, Severity.HIGH, View.DECODED,
                "\\|\\s*(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|python[0-9.]*|perl|powershell|cmd)\\b", "Pipe into an interpreter",
                anyOf("|")));
        r.add(new Rule("CMD_SHELL_PATH", C, Severity.HIGH, View.DECODED,
                "/bin/(?:ba|z|da|k)?sh\\b|cmd(?:\\.exe)?\\s+/c\\b|powershell(?:\\.exe)?\\s+-(?:e|enc|c|command|nop)\\b",
                "Direct interpreter invocation",
                anyOf("/bin/", "cmd", "powershell")));
        r.add(new Rule("CMD_REVERSE_SHELL", C, Severity.HIGH, View.DECODED,
                "\\bnc(?:at)?\\s+(?:-[a-z]*[ec]\\b|.{0,200}?\\s-e\\s)|/dev/tcp/|\\bmkfifo\\b", "Reverse shell pattern",
                anyOf("nc", "/dev/tcp/", "mkfifo")));
        r.add(new Rule("JNDI_LOOKUP", C, Severity.HIGH, View.COMPACT,
                "\\$\\{(?:jndi|\\$\\{|lower:|upper:|env:|sys:|::-)", "JNDI/Log4Shell lookup",
                anyOf("${")));
        r.add(new Rule("EL_INJECTION", C, Severity.HIGH, View.COMPACT,
                "[$#]\\{[^}]{0,200}(?:t\\(java\\.|getruntime|processbuilder|getclass\\(|classloader|forname\\()",
                "Expression-language / OGNL injection",
                anyOf("{"), anyOf("java.", "getruntime", "processbuilder", "getclass(", "classloader", "forname(")));
        r.add(new Rule("SSTI_PROBE", C, Severity.MEDIUM, View.COMPACT,
                "\\{\\{[^}]{0,100}(?:__class__|__globals__|__subclasses__|config\\.|self\\.)", "Server-side template injection",
                anyOf("{{"), anyOf("__class__", "__globals__", "__subclasses__", "config.", "self.")));
        return r;
    }
}
