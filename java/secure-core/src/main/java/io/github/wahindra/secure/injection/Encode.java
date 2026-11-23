package io.github.wahindra.secure.injection;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Contextual output encoders. Pick the one matching where the value lands in the page;
 * HTML-encoding a value placed inside a script block does not make it safe.
 */
public final class Encode {

    private Encode() {
    }

    /** Text between tags: {@code <p>VALUE</p>}. */
    public static String forHtml(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '&': sb.append("&amp;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&#x27;"); break;
                case '/': sb.append("&#x2F;"); break;
                case '`': sb.append("&#x60;"); break;
                default:
                    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                        sb.append(' ');
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /** Quoted attribute value: {@code <input value="VALUE">}. Encodes every non-alphanumeric ASCII char. */
    public static String forHtmlAttribute(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80 && !Character.isLetterOrDigit(c)) {
                sb.append("&#x").append(Integer.toHexString(c)).append(';');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Inside a quoted JavaScript string: {@code var x = 'VALUE';}. Also safe inside a script block. */
    public static String forJavaScript(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80 && !Character.isLetterOrDigit(c) && c != ' ' && c != ',' && c != '.' && c != '_') {
                sb.append(String.format("\\x%02x", (int) c));
            } else if (c == '\u2028' || c == '\u2029') {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** A single query-string value or path segment. */
    public static String forUrlComponent(String s) {
        if (s == null) {
            return "";
        }
        try {
            return URLEncoder.encode(s, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Quoted CSS string value. */
    public static String forCssString(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80 && !Character.isLetterOrDigit(c)) {
                sb.append('\\').append(Integer.toHexString(c)).append(' ');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Returns the URL only if it is http(s), mailto, or relative; otherwise "#". Use for
     * user-supplied href/src values, then also apply {@link #forHtmlAttribute(String)}.
     */
    public static String safeUrl(String url) {
        if (url == null) {
            return "#";
        }
        String t = url.trim();
        StringBuilder scheme = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':') {
                String sch = scheme.toString().toLowerCase(java.util.Locale.ROOT);
                return sch.equals("http") || sch.equals("https") || sch.equals("mailto") ? t : "#";
            }
            if (c == '/' || c == '?' || c == '#') {
                break;
            }
            if (!Character.isWhitespace(c) && !Character.isISOControl(c)) {
                scheme.append(c);
            }
        }
        return t;
    }
}
