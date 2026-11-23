package io.github.wahindra.secure.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC-SHA256 password hashing (available on every Java 8+ JVM, no dependencies).
 * The stored format is shared with the JavaScript package, so either side can verify:
 *
 * <pre>pbkdf2_sha256$600000$&lt;salt b64&gt;$&lt;hash b64&gt;</pre>
 *
 * 600,000 iterations follows the current OWASP Password Storage Cheat Sheet for this algorithm.
 * If you can add a dependency, Argon2id is preferable.
 */
public final class PasswordHasher {

    public static final int DEFAULT_ITERATIONS = 600_000;
    private static final String PREFIX = "pbkdf2_sha256";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BYTES = 32;
    /** Caps work done for a tampered stored hash. */
    private static final int MAX_ITERATIONS = 10_000_000;
    private static final int MAX_PASSWORD_CHARS = 1024;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final int iterations;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < 1 || iterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range");
        }
        this.iterations = iterations;
    }

    public String hash(char[] password) {
        checkLength(password);
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] dk = derive(password, salt, iterations, KEY_BYTES);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return PREFIX + "$" + iterations + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(dk);
    }

    /** Constant-time check. Returns {@code false} for malformed stored values instead of throwing. */
    public boolean verify(char[] password, String stored) {
        if (password == null || password.length > MAX_PASSWORD_CHARS || stored == null) {
            return false;
        }
        String[] parts = stored.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return false;
        }
        try {
            int iter = Integer.parseInt(parts[1]);
            if (iter < 1 || iter > MAX_ITERATIONS) {
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            if (expected.length < 16 || expected.length > 64) {
                return false;
            }
            byte[] actual = derive(password, salt, iter, expected.length);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** True when the stored hash uses fewer iterations than this hasher; re-hash after a successful login. */
    public boolean needsRehash(String stored) {
        String[] parts = stored == null ? new String[0] : stored.split("\\$");
        if (parts.length != 4 || !PREFIX.equals(parts[0])) {
            return true;
        }
        try {
            return Integer.parseInt(parts[1]) < iterations;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    private static void checkLength(char[] password) {
        if (password == null || password.length == 0 || password.length > MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException("password length out of range");
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int keyBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBytes * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Zeroes a password buffer after use. */
    public static void wipe(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}
