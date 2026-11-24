package io.github.wahindra.secure.web;

/**
 * Minimal streaming JSON reader for request inspection. Reports every object key and string
 * value with its path, without building objects. Numbers, booleans and null are skipped, since
 * they cannot carry an injection payload. No dependencies, works on Java 8.
 */
final class JsonScanner {

    /** Receives keys and string values in document order. */
    interface Visitor {
        /** @return {@code false} to stop scanning (for example when a budget is exhausted) */
        boolean onKey(String path, String key);

        /** @return {@code false} to stop scanning */
        boolean onString(String path, String value);
    }

    enum Result { OK, INVALID, TOO_DEEP, STOPPED }

    private final String s;
    private final int maxDepth;
    private final Visitor visitor;
    private int i;
    private boolean stopped;

    private JsonScanner(String s, int maxDepth, Visitor visitor) {
        this.s = s;
        this.maxDepth = maxDepth;
        this.visitor = visitor;
    }

    static Result scan(String json, int maxDepth, Visitor visitor) {
        JsonScanner p = new JsonScanner(json, maxDepth, visitor);
        try {
            p.ws();
            p.value("body", 0);
            p.ws();
            if (p.stopped) {
                return Result.STOPPED;
            }
            return p.i == p.s.length() ? Result.OK : Result.INVALID;
        } catch (TooDeep e) {
            return Result.TOO_DEEP;
        } catch (Invalid e) {
            return p.stopped ? Result.STOPPED : Result.INVALID;
        }
    }

    private static final class Invalid extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Invalid() {
            super(null, null, false, false);
        }
    }

    private static final class TooDeep extends RuntimeException {
        private static final long serialVersionUID = 1L;

        TooDeep() {
            super(null, null, false, false);
        }
    }

    private void value(String path, int depth) {
        if (stopped) {
            throw new Invalid();
        }
        if (i >= s.length()) {
            throw new Invalid();
        }
        char c = s.charAt(i);
        if (c == '{' || c == '[') {
            if (depth >= maxDepth) {
                throw new TooDeep();
            }
            if (c == '{') {
                object(path, depth + 1);
            } else {
                array(path, depth + 1);
            }
        } else if (c == '"') {
            String v = string();
            if (!visitor.onString(path, v)) {
                stopped = true;
                throw new Invalid();
            }
        } else if (c == 't') {
            literal("true");
        } else if (c == 'f') {
            literal("false");
        } else if (c == 'n') {
            literal("null");
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            number();
        } else {
            throw new Invalid();
        }
    }

    private void object(String path, int depth) {
        i++; // {
        ws();
        if (peek() == '}') {
            i++;
            return;
        }
        while (true) {
            ws();
            if (peek() != '"') {
                throw new Invalid();
            }
            String key = string();
            String child = path + "." + key;
            if (!visitor.onKey(child, key)) {
                stopped = true;
                throw new Invalid();
            }
            ws();
            expect(':');
            ws();
            value(child, depth);
            ws();
            char c = peek();
            i++;
            if (c == '}') {
                return;
            }
            if (c != ',') {
                throw new Invalid();
            }
        }
    }

    private void array(String path, int depth) {
        i++; // [
        ws();
        if (peek() == ']') {
            i++;
            return;
        }
        int index = 0;
        while (true) {
            ws();
            value(path + "[" + index++ + "]", depth);
            ws();
            char c = peek();
            i++;
            if (c == ']') {
                return;
            }
            if (c != ',') {
                throw new Invalid();
            }
        }
    }

    private String string() {
        i++; // opening quote
        StringBuilder sb = null;
        int start = i;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '"') {
                String v = sb == null ? s.substring(start, i) : sb.append(s, start, i).toString();
                i++;
                return v;
            }
            if (c == '\\') {
                if (sb == null) {
                    sb = new StringBuilder();
                }
                sb.append(s, start, i);
                if (i + 1 >= s.length()) {
                    throw new Invalid();
                }
                char e = s.charAt(i + 1);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 6 > s.length()) {
                            throw new Invalid();
                        }
                        try {
                            sb.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                        } catch (NumberFormatException ex) {
                            throw new Invalid();
                        }
                        i += 4;
                        break;
                    default:
                        throw new Invalid();
                }
                i += 2;
                start = i;
            } else if (c < 0x20) {
                throw new Invalid();
            } else {
                i++;
            }
        }
        throw new Invalid();
    }

    private void number() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
            i++;
        }
        if (i == start) {
            throw new Invalid();
        }
    }

    private void literal(String word) {
        if (!s.startsWith(word, i)) {
            throw new Invalid();
        }
        i += word.length();
    }

    private void expect(char c) {
        if (peek() != c) {
            throw new Invalid();
        }
        i++;
    }

    private char peek() {
        if (i >= s.length()) {
            throw new Invalid();
        }
        return s.charAt(i);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                return;
            }
        }
    }
}
