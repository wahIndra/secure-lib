package io.github.wahindra.secure.logging;

import java.util.regex.Pattern;

/**
 * Makes untrusted values safe to write to logs: neutralizes CR/LF (log forging), strips
 * control characters, masks secrets and truncates. Apply to every user-controlled value
 * before logging it.
 */
public final class LogSanitizer {

    public static final int DEFAULT_MAX_LENGTH = 1000;

    private static final Pattern KEY_VALUE_SECRET = Pattern.compile(
            "(?i)(\"?(?:password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|client_secret"
                    + "|authorization|cookie|session(?:id)?|jsessionid|private[_-]?key)\"?\\s*[=:]\\s*\"?)"
                    + "(?!(?i:bearer|basic)\\s)([^\\s\"&,;]+)");
    private static final Pattern BEARER = Pattern.compile("(?i)\\b(bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}");

    private LogSanitizer() {
    }

    public static String sanitize(String value) {
        return sanitize(value, DEFAULT_MAX_LENGTH);
    }

    public static String sanitize(String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        String v = value.length() > maxLength * 4 ? value.substring(0, maxLength * 4) : value;
        v = maskSecrets(v);
        StringBuilder sb = new StringBuilder(Math.min(v.length(), maxLength) + 16);
        for (int i = 0; i < v.length() && sb.length() < maxLength; i++) {
            char c = v.charAt(i);
            if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\t') {
                sb.append("\\t");
            } else if (Character.isISOControl(c) || c == '\u2028' || c == '\u2029' || c == '\u0085') {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        if (sb.length() >= maxLength && v.length() > maxLength) {
            sb.append("...[truncated]");
        }
        return sb.toString();
    }

    public static String maskSecrets(String value) {
        if (value == null) {
            return null;
        }
        String v = KEY_VALUE_SECRET.matcher(value).replaceAll("$1****");
        v = BEARER.matcher(v).replaceAll("$1 ****");
        return JWT.matcher(v).replaceAll("eyJ****");
    }
}
