package io.github.wahindra.secure.injection;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Builds a {@link ProcessBuilder} from a fixed executable and validated arguments, with no shell
 * in between, so metacharacters in arguments are never interpreted.
 *
 * <pre>
 * Process p = SafeCommand.of("/usr/bin/convert").arg(inputFile).arg(outputFile).build().start();
 * </pre>
 */
public final class SafeCommand {

    private static final List<String> SHELLS = Arrays.asList(
            "sh", "bash", "zsh", "dash", "ksh", "csh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh");
    private static final Pattern SAFE_ARG = Pattern.compile("[A-Za-z0-9._,:=@/\\\\+-]{1,1024}");

    private final List<String> command = new ArrayList<String>();

    private SafeCommand(String executable) {
        String name = executable.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1).toLowerCase(java.util.Locale.ROOT);
        if (SHELLS.contains(name)) {
            throw violation("shell interpreters are not allowed as the executable");
        }
        command.add(executable);
    }

    public static SafeCommand of(String executable) {
        if (executable == null || executable.isEmpty()) {
            throw violation("executable is required");
        }
        return new SafeCommand(executable);
    }

    /** Adds a user-influenced argument. Rejects option injection (leading '-') and shell metacharacters. */
    public SafeCommand arg(String value) {
        if (value == null || !SAFE_ARG.matcher(value).matches() || value.startsWith("-")) {
            throw violation("unsafe command argument");
        }
        command.add(value);
        return this;
    }

    /** Adds a constant option written by the developer, e.g. {@code "--quality"}. Never pass user input here. */
    public SafeCommand option(String constantOption) {
        command.add(constantOption);
        return this;
    }

    public List<String> toList() {
        return Collections.unmodifiableList(command);
    }

    public ProcessBuilder build() {
        return new ProcessBuilder(command);
    }

    private static SecurityViolationException violation(String msg) {
        return new SecurityViolationException(OwaspCategory.INJECTION, msg);
    }
}
