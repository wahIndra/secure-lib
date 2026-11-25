package io.github.wahindra.secure.web;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Decodes a JSON request body every way the application's parser might, so that inspection and
 * parsing cannot disagree. Jackson (Spring) detects UTF-8/16/32 from the first bytes, as the JSON
 * RFCs allow; other code honours the declared {@code charset}. Both readings are returned, each
 * decoded strictly. A body that does not decode cleanly in any of them is rejected by the caller.
 */
final class JsonBodies {

    private static final Charset UTF_32BE = Charset.forName("UTF-32BE");
    private static final Charset UTF_32LE = Charset.forName("UTF-32LE");

    private JsonBodies() {
    }

    /**
     * @return the distinct strict decodings, or an empty list if none succeeded (fail closed)
     */
    static List<String> decode(byte[] body, String declaredCharset) {
        Set<Charset> candidates = new LinkedHashSet<Charset>();
        candidates.add(detect(body));
        Charset declared = parse(declaredCharset);
        if (declared != null) {
            candidates.add(declared);
        }
        Set<String> out = new LinkedHashSet<String>();
        for (Charset cs : candidates) {
            String text = strict(body, bomLength(body, cs), cs);
            if (text != null) {
                out.add(text);
            }
        }
        return new ArrayList<String>(out);
    }

    /** RFC 4627 section 3 / RFC 8259: BOM first, then the pattern of zero bytes in the first four. */
    static Charset detect(byte[] b) {
        int n = b.length;
        int b0 = n > 0 ? b[0] & 0xff : -1;
        int b1 = n > 1 ? b[1] & 0xff : -1;
        int b2 = n > 2 ? b[2] & 0xff : -1;
        int b3 = n > 3 ? b[3] & 0xff : -1;
        if (b0 == 0x00 && b1 == 0x00 && b2 == 0xfe && b3 == 0xff) {
            return UTF_32BE;
        }
        if (b0 == 0xff && b1 == 0xfe && b2 == 0x00 && b3 == 0x00) {
            return UTF_32LE;
        }
        if (b0 == 0xfe && b1 == 0xff) {
            return StandardCharsets.UTF_16BE;
        }
        if (b0 == 0xff && b1 == 0xfe) {
            return StandardCharsets.UTF_16LE;
        }
        if (n >= 4) {
            if (b0 == 0 && b1 == 0 && b2 == 0 && b3 != 0) {
                return UTF_32BE;
            }
            if (b0 != 0 && b1 == 0 && b2 == 0 && b3 == 0) {
                return UTF_32LE;
            }
            if (b0 == 0 && b1 != 0 && b2 == 0 && b3 != 0) {
                return StandardCharsets.UTF_16BE;
            }
            if (b0 != 0 && b1 == 0 && b2 != 0 && b3 == 0) {
                return StandardCharsets.UTF_16LE;
            }
        } else if (n >= 2) {
            if (b0 == 0 && b1 != 0) {
                return StandardCharsets.UTF_16BE;
            }
            if (b0 != 0 && b1 == 0) {
                return StandardCharsets.UTF_16LE;
            }
        }
        return StandardCharsets.UTF_8;
    }

    private static int bomLength(byte[] b, Charset cs) {
        if (cs.equals(StandardCharsets.UTF_8) && b.length >= 3 && (b[0] & 0xff) == 0xef && (b[1] & 0xff) == 0xbb && (b[2] & 0xff) == 0xbf) {
            return 3;
        }
        if ((cs.equals(UTF_32BE) || cs.equals(UTF_32LE)) && b.length >= 4
                && (((b[0] & 0xff) == 0x00 && (b[1] & 0xff) == 0x00 && (b[2] & 0xff) == 0xfe && (b[3] & 0xff) == 0xff)
                || ((b[0] & 0xff) == 0xff && (b[1] & 0xff) == 0xfe && (b[2] & 0xff) == 0x00 && (b[3] & 0xff) == 0x00))) {
            return 4;
        }
        if ((cs.equals(StandardCharsets.UTF_16BE) || cs.equals(StandardCharsets.UTF_16LE)) && b.length >= 2
                && (((b[0] & 0xff) == 0xfe && (b[1] & 0xff) == 0xff) || ((b[0] & 0xff) == 0xff && (b[1] & 0xff) == 0xfe))) {
            return 2;
        }
        return 0;
    }

    private static String strict(byte[] body, int offset, Charset cs) {
        CharsetDecoder d = cs.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer chars = d.decode(ByteBuffer.wrap(body, offset, body.length - offset));
            return chars.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** The {@code charset} parameter of a Content-Type, or {@code null} if absent or unknown. */
    static Charset parse(String charsetName) {
        if (charsetName == null || charsetName.trim().isEmpty()) {
            return null;
        }
        try {
            return Charset.forName(charsetName.trim().replace("\"", ""));
        } catch (RuntimeException e) {
            return null;
        }
    }
}
