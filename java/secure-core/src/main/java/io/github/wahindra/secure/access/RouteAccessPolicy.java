package io.github.wahindra.secure.access;

import io.github.wahindra.secure.detect.InputNormalizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Deny-by-default route authorization. Rules are checked in order and the first match
 * wins; a request matching no rule is denied.
 *
 * <p>Paths are canonicalized before matching to close common bypasses: {@code /admin/../},
 * {@code //admin}, {@code /admin;jsessionid=x}, {@code /%61dmin}, {@code /ADMIN},
 * {@code /admin/} and encoded slashes. Requests whose path cannot be canonicalized safely
 * are denied.
 *
 * <pre>
 * RouteAccessPolicy policy = RouteAccessPolicy.builder()
 *     .permitAll("GET", "/public/**")
 *     .permitAll("POST", "/login")
 *     .hasAnyRole("*", "/admin/**", "ADMIN")
 *     .authenticated("*", "/api/**")
 *     .build();
 * policy.check("GET", request.getRequestURI(), currentUser);
 * </pre>
 */
public final class RouteAccessPolicy {

    private enum Kind { PERMIT_ALL, AUTHENTICATED, ROLES, DENY }

    private static final class RouteRule {
        final String method;
        final String[] pattern;
        final Kind kind;
        final List<String> roles;
        final String source;

        RouteRule(String method, String pattern, Kind kind, List<String> roles, boolean ignoreCase) {
            this.method = method.toUpperCase(Locale.ROOT);
            String p = ignoreCase ? pattern.toLowerCase(Locale.ROOT) : pattern;
            this.pattern = segments(p);
            this.kind = kind;
            this.roles = roles;
            this.source = method + " " + pattern;
        }
    }

    private final List<RouteRule> rules;
    private final boolean ignoreCase;

    private RouteAccessPolicy(Builder b) {
        this.rules = Collections.unmodifiableList(new ArrayList<RouteRule>(b.rules));
        this.ignoreCase = b.ignoreCase;
    }

    public static Builder builder() {
        return new Builder();
    }

    public AccessDecision evaluate(String method, String rawPath, SecurityPrincipal principal) {
        String path = canonicalize(rawPath);
        if (path == null) {
            return AccessDecision.deny("non-canonical path", null, false);
        }
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        String[] segs = segments(ignoreCase ? path.toLowerCase(Locale.ROOT) : path);
        for (RouteRule rule : rules) {
            if (!"*".equals(rule.method) && !rule.method.equals(m)) {
                continue;
            }
            if (!matches(rule.pattern, 0, segs, 0)) {
                continue;
            }
            boolean authenticated = principal != null && principal.getId() != null && !principal.getId().isEmpty();
            switch (rule.kind) {
                case PERMIT_ALL:
                    return AccessDecision.allow(rule.source);
                case DENY:
                    return AccessDecision.deny("route denied", rule.source, false);
                case AUTHENTICATED:
                    return authenticated ? AccessDecision.allow(rule.source)
                            : AccessDecision.deny("authentication required", rule.source, true);
                default:
                    if (!authenticated) {
                        return AccessDecision.deny("authentication required", rule.source, true);
                    }
                    return AccessGuard.hasAnyRole(principal, rule.roles.toArray(new String[0]))
                            ? AccessDecision.allow(rule.source)
                            : AccessDecision.deny("missing required role", rule.source, false);
            }
        }
        return AccessDecision.deny("no matching rule (deny by default)", null, false);
    }

    /** Throws {@link AccessDeniedException} when the request is not allowed. */
    public void check(String method, String rawPath, SecurityPrincipal principal) {
        AccessDecision d = evaluate(method, rawPath, principal);
        if (!d.isAllowed()) {
            throw new AccessDeniedException(d.getReason(), d.isUnauthenticated());
        }
    }

    /**
     * Returns the canonical form of a request path (query string removed), or {@code null}
     * if it contains traversal, encoded separators, backslashes, null bytes or path parameters.
     */
    public static String canonicalize(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return "/";
        }
        String p = rawPath;
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        int h = p.indexOf('#');
        if (h >= 0) {
            p = p.substring(0, h);
        }
        String lower = p.toLowerCase(Locale.ROOT);
        if (lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") || lower.contains("%25")) {
            return null;
        }
        String decoded = InputNormalizer.decode(p);
        if (decoded.indexOf('\\') >= 0 || decoded.indexOf('\0') >= 0 || decoded.indexOf(';') >= 0) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        for (String seg : decoded.split("/+")) {
            if (seg.isEmpty()) {
                continue;
            }
            if (!isUnambiguousSegment(seg)) {
                return null;
            }
            out.append('/').append(seg);
        }
        return out.length() == 0 ? "/" : out.toString();
    }

    /**
     * Rejects segments that some servers rewrite before routing, so the policy and the router
     * cannot disagree: dot-only segments, leading/trailing whitespace ("admin " or "%20admin"),
     * trailing dots ("admin." is "admin" on Windows/IIS), and control or invisible characters.
     */
    private static boolean isUnambiguousSegment(String seg) {
        if (seg.replace(".", "").isEmpty() || seg.endsWith(".")) {
            return false;
        }
        for (int i = 0; i < seg.length(); i++) {
            char c = seg.charAt(i);
            boolean edge = i == 0 || i == seg.length() - 1;
            if (Character.isISOControl(c) || (edge && (Character.isWhitespace(c) || Character.isSpaceChar(c)))
                    || Character.getType(c) == Character.FORMAT) {
                return false;
            }
        }
        return true;
    }

    private static String[] segments(String path) {
        List<String> s = new ArrayList<String>();
        for (String seg : path.split("/+")) {
            if (!seg.isEmpty()) {
                s.add(seg);
            }
        }
        return s.toArray(new String[0]);
    }

    /** Ant-style match: '*' matches one segment (or part of one), '**' matches zero or more segments. */
    private static boolean matches(String[] pattern, int pi, String[] path, int si) {
        if (pi == pattern.length) {
            return si == path.length;
        }
        if ("**".equals(pattern[pi])) {
            for (int k = si; k <= path.length; k++) {
                if (matches(pattern, pi + 1, path, k)) {
                    return true;
                }
            }
            return false;
        }
        return si < path.length && segmentMatches(pattern[pi], path[si]) && matches(pattern, pi + 1, path, si + 1);
    }

    private static boolean segmentMatches(String pattern, String segment) {
        if ("*".equals(pattern)) {
            return true;
        }
        if (pattern.indexOf('*') < 0) {
            return pattern.equals(segment);
        }
        String[] parts = pattern.split("\\*", -1);
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                regex.append(".*");
            }
            regex.append(java.util.regex.Pattern.quote(parts[i]));
        }
        return segment.matches(regex.toString());
    }

    public static final class Builder {
        private final List<RouteRule> rules = new ArrayList<RouteRule>();
        private boolean ignoreCase = true;

        /**
         * Case-insensitive matching is the default because many servers route {@code /ADMIN}
         * to the same handler as {@code /admin}. Only disable if your router is strictly case-sensitive.
         */
        public Builder ignoreCase(boolean value) {
            ignoreCase = value;
            return this;
        }

        public Builder permitAll(String method, String pattern) {
            return add(method, pattern, Kind.PERMIT_ALL, Collections.<String>emptyList());
        }

        public Builder authenticated(String method, String pattern) {
            return add(method, pattern, Kind.AUTHENTICATED, Collections.<String>emptyList());
        }

        public Builder hasAnyRole(String method, String pattern, String... roles) {
            if (roles.length == 0) {
                throw new IllegalArgumentException("at least one role is required");
            }
            return add(method, pattern, Kind.ROLES, Arrays.asList(roles));
        }

        public Builder denyAll(String method, String pattern) {
            return add(method, pattern, Kind.DENY, Collections.<String>emptyList());
        }

        private Builder add(String method, String pattern, Kind kind, List<String> roles) {
            rules.add(new RouteRule(method, pattern, kind, roles, ignoreCase));
            return this;
        }

        public RouteAccessPolicy build() {
            return new RouteAccessPolicy(this);
        }
    }
}
