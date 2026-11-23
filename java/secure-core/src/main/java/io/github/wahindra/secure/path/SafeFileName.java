package io.github.wahindra.secure.path;

import java.util.Locale;
import java.util.regex.Pattern;

/** Validation and sanitizing of single file names, e.g. for uploads. Portable across Windows and Unix. */
public final class SafeFileName {

    private static final Pattern ALLOWED = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._ -]{0,254}");
    private static final Pattern WINDOWS_RESERVED = Pattern.compile("(?i)(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\\..*)?");
    private static final int MAX_LENGTH = 255;

    private SafeFileName() {
    }

    public static boolean isSafe(String name) {
        return name != null
                && ALLOWED.matcher(name).matches()
                && !name.contains("..")
                && !name.endsWith(".") && !name.endsWith(" ")
                && !WINDOWS_RESERVED.matcher(name).matches();
    }

    public static String require(String name) {
        if (!isSafe(name)) {
            throw new PathTraversalException("unsafe file name");
        }
        return name;
    }

    /**
     * Produces a safe name from untrusted input: path components are dropped, disallowed
     * characters become '_', reserved names are prefixed. Never returns an empty string.
     */
    public static String sanitize(String name) {
        String n = name == null ? "" : name;
        n = n.substring(Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\')) + 1);
        StringBuilder sb = new StringBuilder(n.length());
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-' || c == ' ';
            sb.append(ok ? c : '_');
        }
        String s = sb.toString().replaceAll("\\.{2,}", ".");
        s = s.replaceAll("^[. _-]+", "").replaceAll("[. ]+$", "");
        if (s.length() > MAX_LENGTH) {
            int dot = s.lastIndexOf('.');
            String ext = dot > 0 && s.length() - dot <= 16 ? s.substring(dot) : "";
            s = s.substring(0, MAX_LENGTH - ext.length()) + ext;
        }
        if (s.isEmpty()) {
            s = "file";
        }
        if (WINDOWS_RESERVED.matcher(s).matches()) {
            s = "_" + s;
        }
        return s;
    }

    /** Lower-case extension without the dot, or "" if there is none. */
    public static String extension(String name) {
        int dot = name == null ? -1 : name.lastIndexOf('.');
        return dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
