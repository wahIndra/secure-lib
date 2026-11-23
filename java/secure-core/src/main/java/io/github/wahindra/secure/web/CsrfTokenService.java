package io.github.wahindra.secure.web;

import io.github.wahindra.secure.crypto.SecureTokens;
import io.github.wahindra.secure.integrity.HmacSigner;

/**
 * Stateless CSRF tokens bound to the session: {@code nonce.HMAC(sessionId|nonce)}. Embed the
 * token in forms or an {@code X-CSRF-Token} header and verify on every state-changing request.
 * Pair with {@code SameSite=Lax} (or Strict) session cookies.
 */
public final class CsrfTokenService {

    private final HmacSigner signer;

    /** @param secretKey at least 32 random bytes, kept server-side */
    public CsrfTokenService(byte[] secretKey) {
        this.signer = new HmacSigner(secretKey);
    }

    public String generate(String sessionId) {
        requireSession(sessionId);
        String nonce = SecureTokens.urlSafe(16);
        return nonce + "." + signer.sign(sessionId + "|" + nonce);
    }

    public boolean verify(String sessionId, String token) {
        if (sessionId == null || sessionId.isEmpty() || token == null || token.length() > 256) {
            return false;
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            return false;
        }
        String nonce = token.substring(0, dot);
        return signer.verify(sessionId + "|" + nonce, token.substring(dot + 1));
    }

    /** Safe methods do not need a token; everything else does. */
    public static boolean requiresToken(String method) {
        return !("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method) || "TRACE".equalsIgnoreCase(method));
    }

    private static void requireSession(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("session id required");
        }
    }
}
