package io.github.wahindra.secure.web;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Fixes open redirects ({@code ?next=https://evil.example}): only relative paths on this site, or
 * absolute http(s) URLs to hosts you list, are accepted. Anything else becomes the fallback.
 *
 * <pre>
 * response.sendRedirect(SafeRedirect.target(request.getParameter("next"), "/", "accounts.example.com"));
 * </pre>
 *
 * <p>Rejected: protocol-relative {@code //evil}, {@code /\evil} and other backslash tricks (browsers
 * treat {@code \} as {@code /}), {@code javascript:} and other schemes, credentials in the URL
 * ({@code https://good@evil}), control characters and line breaks (header injection), and
 * encoded slashes at the start ({@code /%2F%2Fevil}).
 */
public final class SafeRedirect {

    private SafeRedirect() {
    }

    /**
     * @param requested    the user-supplied target, e.g. a {@code next} or {@code returnUrl} parameter
     * @param fallback     where to go when {@code requested} is unsafe, e.g. {@code "/"}
     * @param allowedHosts hosts allowed for absolute URLs: exact names or {@code *.example.com}
     */
    public static String target(String requested, String fallback, String... allowedHosts) {
        return isSafe(requested, allowedHosts) ? requested.trim() : fallback;
    }

    public static boolean isSafe(String requested, String... allowedHosts) {
        if (requested == null) {
            return false;
        }
        String t = requested.trim();
        if (t.isEmpty() || t.length() > 2048) {
            return false;
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c < 0x20 || c == 0x7f || c == '\\') {
                return false;
            }
        }
        if (t.startsWith("/")) {
            // "/" alone or "/path"; never "//host" or an encoded slash that a later decode turns into one.
            String lower = t.toLowerCase(Locale.ROOT);
            return !t.startsWith("//") && !lower.startsWith("/%2f") && !lower.startsWith("/%5c");
        }
        URI uri;
        try {
            uri = new URI(t);
        } catch (URISyntaxException e) {
            return false;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            return false;
        }
        if (uri.getRawUserInfo() != null || uri.getHost() == null) {
            return false;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        for (String allowed : allowedHosts) {
            String a = allowed.toLowerCase(Locale.ROOT);
            if (a.startsWith("*.") ? host.endsWith(a.substring(1)) && host.length() > a.length() - 1 : host.equals(a)) {
                return true;
            }
        }
        return false;
    }
}
