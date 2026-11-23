package io.github.wahindra.secure.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Unguessable tokens (session ids, reset links, API keys) and timing-safe comparison. */
public final class SecureTokens {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureTokens() {
    }

    /** URL-safe random token; 32 bytes gives 256 bits of entropy. */
    public static String urlSafe(int bytes) {
        if (bytes < 16) {
            throw new IllegalArgumentException("use at least 16 bytes (128 bits)");
        }
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static String urlSafe() {
        return urlSafe(32);
    }

    /** Constant-time string comparison. Use for tokens, signatures and API keys. */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * SHA-256 of a high-entropy token, for storing reset tokens or API keys so a database leak
     * does not leak usable credentials. Not for passwords; use {@link PasswordHasher}.
     */
    public static String sha256(String token) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
