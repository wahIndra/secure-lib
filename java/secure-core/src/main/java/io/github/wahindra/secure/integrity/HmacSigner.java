package io.github.wahindra.secure.integrity;

import io.github.wahindra.secure.crypto.SecureTokens;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 signing for data that leaves the server and comes back (cookies, hidden fields,
 * signed URLs) and for verifying webhooks. Output is unpadded base64url.
 */
public final class HmacSigner {

    private static final String ALG = "HmacSHA256";

    private final SecretKeySpec key;

    public HmacSigner(byte[] secretKey) {
        if (secretKey == null || secretKey.length < 32) {
            throw new IllegalArgumentException("HMAC key must be at least 32 bytes");
        }
        this.key = new SecretKeySpec(secretKey.clone(), ALG);
    }

    public String sign(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac(data.getBytes(StandardCharsets.UTF_8)));
    }

    public boolean verify(String data, String signature) {
        if (data == null || signature == null) {
            return false;
        }
        return SecureTokens.constantTimeEquals(sign(data), signature);
    }

    /** Hex signature, the common format for webhook headers such as {@code X-Hub-Signature-256: sha256=<hex>}. */
    public boolean verifyHex(byte[] payload, String hexSignature) {
        if (payload == null || hexSignature == null) {
            return false;
        }
        String sig = hexSignature.startsWith("sha256=") ? hexSignature.substring(7) : hexSignature;
        byte[] m = mac(payload);
        StringBuilder hex = new StringBuilder(m.length * 2);
        for (byte b : m) {
            hex.append(String.format("%02x", b & 0xff));
        }
        return SecureTokens.constantTimeEquals(hex.toString(), sig.toLowerCase(java.util.Locale.ROOT));
    }

    private byte[] mac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(ALG);
            mac.init(key);
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
