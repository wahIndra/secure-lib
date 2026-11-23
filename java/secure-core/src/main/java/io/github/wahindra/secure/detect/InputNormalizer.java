package io.github.wahindra.secure.detect;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Undoes the encodings attackers stack to slip past filters: repeated URL encoding,
 * IIS %uXXXX, overlong UTF-8, HTML entities, full-width Unicode and odd whitespace.
 */
public final class InputNormalizer {

    private static final int MAX_DECODE_PASSES = 3;

    private static final Pattern NUMERIC_ENTITY = Pattern.compile("&#(x[0-9a-fA-F]{1,6}|[0-9]{1,7});?");
    private static final Pattern NAMED_ENTITY = Pattern.compile("&([a-zA-Z]{2,8});");
    private static final Map<String, String> NAMED = new HashMap<String, String>();

    static {
        NAMED.put("lt", "<");
        NAMED.put("gt", ">");
        NAMED.put("quot", "\"");
        NAMED.put("apos", "'");
        NAMED.put("amp", "&");
        NAMED.put("colon", ":");
        NAMED.put("semi", ";");
        NAMED.put("tab", "\t");
        NAMED.put("newline", "\n");
        NAMED.put("lpar", "(");
        NAMED.put("rpar", ")");
        NAMED.put("sol", "/");
        NAMED.put("bsol", "\\");
        NAMED.put("period", ".");
        NAMED.put("nbsp", " ");
    }

    private InputNormalizer() {
    }

    /** Decoded, NFKC-normalized, case preserved. Use when the exact value still matters (file names). */
    public static String decode(String input) {
        if (input == null) {
            return "";
        }
        String s = input;
        for (int i = 0; i < MAX_DECODE_PASSES; i++) {
            String next = decodeHtmlEntities(percentDecode(replaceOverlongUtf8(s)));
            if (next.equals(s)) {
                break;
            }
            s = next;
        }
        return isAscii(s) ? s : Normalizer.normalize(s, Normalizer.Form.NFKC);
    }

    /** Pure ASCII is already NFKC-normalized, so the (comparatively slow) normalizer can be skipped. */
    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) >= 0x80) {
                return false;
            }
        }
        return true;
    }

    /** {@link #decode(String)}, lower-cased, with every whitespace or control run collapsed to one space. */
    public static String normalize(String input) {
        String s = decode(input).toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder(s.length());
        boolean lastSpace = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // \0 is kept: the path detector reports null-byte injection.
            boolean space = c != '\0' && (Character.isWhitespace(c) || Character.isSpaceChar(c) || Character.isISOControl(c));
            if (space) {
                if (!lastSpace) {
                    sb.append(' ');
                }
                lastSpace = true;
            } else {
                sb.append(c);
                lastSpace = false;
            }
        }
        return sb.toString().trim();
    }

    private static String replaceOverlongUtf8(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        return s.replaceAll("(?i)%c0%ae|%e0%80%ae|%c0%2e", ".")
                .replaceAll("(?i)%c0%af|%e0%80%af|%c0%2f", "/")
                .replaceAll("(?i)%c1%9c|%c1%1c|%c0%5c", "\\\\");
    }

    /** Lenient percent decoding: malformed escapes are left as-is, '+' is not treated as space. */
    static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '%' && i + 1 < s.length() && (s.charAt(i + 1) == 'u' || s.charAt(i + 1) == 'U')
                    && isHex(s, i + 2, 4)) {
                flush(bytes, out);
                out.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                i += 6;
            } else if (c == '%' && isHex(s, i + 1, 2)) {
                bytes.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 3;
            } else {
                flush(bytes, out);
                out.append(c);
                i++;
            }
        }
        flush(bytes, out);
        return out.toString();
    }

    private static boolean isHex(String s, int from, int len) {
        if (from + len > s.length()) {
            return false;
        }
        for (int i = from; i < from + len; i++) {
            if (Character.digit(s.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private static void flush(ByteArrayOutputStream bytes, StringBuilder out) {
        if (bytes.size() > 0) {
            out.append(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
            bytes.reset();
        }
    }

    private static String decodeHtmlEntities(String s) {
        if (s.indexOf('&') < 0) {
            return s;
        }
        Matcher m = NUMERIC_ENTITY.matcher(s);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String num = m.group(1);
            int cp = num.charAt(0) == 'x' || num.charAt(0) == 'X'
                    ? Integer.parseInt(num.substring(1), 16)
                    : Integer.parseInt(num);
            String rep = Character.isValidCodePoint(cp) ? new String(Character.toChars(cp)) : m.group();
            m.appendReplacement(sb, Matcher.quoteReplacement(rep));
        }
        m.appendTail(sb);

        m = NAMED_ENTITY.matcher(sb.toString());
        StringBuffer named = new StringBuffer();
        while (m.find()) {
            String rep = NAMED.get(m.group(1).toLowerCase(Locale.ROOT));
            m.appendReplacement(named, Matcher.quoteReplacement(rep != null ? rep : m.group()));
        }
        m.appendTail(named);
        return named.toString();
    }
}
