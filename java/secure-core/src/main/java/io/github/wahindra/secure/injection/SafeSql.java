package io.github.wahindra.secure.injection;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Helpers for the parts of SQL that a {@code PreparedStatement} cannot parameterize:
 * identifiers (ORDER BY column, table name), sort direction, IN-list size and LIKE patterns.
 *
 * <pre>
 * String col = SafeSql.allowlisted(request.getParameter("sort"), SORTABLE_COLUMNS);
 * String sql = "SELECT * FROM orders WHERE owner_id = ? ORDER BY " + col + " " + SafeSql.direction(dir);
 * </pre>
 */
public final class SafeSql {

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final int MAX_IN_LIST = 1000;

    private SafeSql() {
    }

    /** Returns the value only if it is one of the allowed identifiers (case-insensitive), otherwise throws. */
    public static String allowlisted(String value, Collection<String> allowed) {
        if (value != null) {
            for (String a : allowed) {
                if (a.equalsIgnoreCase(value.trim())) {
                    return a;
                }
            }
        }
        throw violation("identifier not in allowlist");
    }

    /**
     * Maps a public name to a real column, e.g. {@code "created" -> "o.created_at"}, so database
     * names never come from the request.
     */
    public static String mapped(String value, Map<String, String> publicToColumn) {
        String column = value == null ? null : publicToColumn.get(value.trim().toLowerCase(Locale.ROOT));
        if (column == null) {
            throw violation("identifier not in allowlist");
        }
        return column;
    }

    /** Validates a plain identifier and wraps it in double quotes (ANSI / PostgreSQL). */
    public static String quoteIdentifier(String name) {
        if (name == null || !IDENTIFIER.matcher(name).matches()) {
            throw violation("invalid SQL identifier");
        }
        return '"' + name + '"';
    }

    /** "ASC" or "DESC"; anything else falls back to {@code defaultDirection}. */
    public static String direction(String value, String defaultDirection) {
        if (value != null) {
            String v = value.trim().toUpperCase(Locale.ROOT);
            if ("ASC".equals(v) || "DESC".equals(v)) {
                return v;
            }
        }
        return "DESC".equalsIgnoreCase(defaultDirection) ? "DESC" : "ASC";
    }

    public static String direction(String value) {
        return direction(value, "ASC");
    }

    /** "?, ?, ?" for an IN clause; bind the values separately. */
    public static String placeholders(int count) {
        if (count < 1 || count > MAX_IN_LIST) {
            throw violation("IN list size must be between 1 and " + MAX_IN_LIST);
        }
        StringBuilder sb = new StringBuilder(count * 3);
        for (int i = 0; i < count; i++) {
            sb.append(i == 0 ? "?" : ", ?");
        }
        return sb.toString();
    }

    /**
     * Escapes %, _ and the escape char so user text is matched literally. Use with
     * {@code LIKE ? ESCAPE '\'} and bind the result as a parameter.
     */
    public static String escapeLike(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '%' || c == '_') {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** Clamps LIMIT/OFFSET style numbers parsed from the request. */
    public static int clamp(String value, int min, int max, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            int n = Integer.parseInt(value.trim());
            return Math.max(min, Math.min(max, n));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static SecurityViolationException violation(String msg) {
        return new SecurityViolationException(OwaspCategory.INJECTION, msg);
    }
}
