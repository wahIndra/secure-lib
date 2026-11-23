package io.github.wahindra.secure.ssrf;

import io.github.wahindra.secure.OwaspCategory;
import io.github.wahindra.secure.SecurityViolationException;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Validates outbound URLs built from user input (webhooks, image fetchers, URL previews).
 *
 * <p>The host is resolved and every address is checked, so DNS names pointing at internal
 * ranges are caught. To stop DNS rebinding, connect to {@link ValidatedUrl#getAddresses()}
 * rather than resolving again, and disable automatic redirects (or validate each hop).
 *
 * <pre>
 * UrlGuard guard = UrlGuard.builder().allowHosts("api.partner.com", "*.cdn.example.com").build();
 * ValidatedUrl url = guard.validate(userUrl);   // throws SsrfException
 * </pre>
 */
public final class UrlGuard {

    /** DNS lookup hook, replaceable in tests. */
    public interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private final Set<String> schemes;
    private final Set<String> hosts;
    private final Set<Integer> ports;
    private final boolean allowPrivate;
    private final HostResolver resolver;

    private UrlGuard(Builder b) {
        this.schemes = Collections.unmodifiableSet(new LinkedHashSet<String>(b.schemes));
        this.hosts = Collections.unmodifiableSet(new LinkedHashSet<String>(b.hosts));
        this.ports = Collections.unmodifiableSet(new LinkedHashSet<Integer>(b.ports));
        this.allowPrivate = b.allowPrivate;
        this.resolver = b.resolver;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** http/https on ports 80/443 to any public address. */
    public static UrlGuard defaults() {
        return builder().build();
    }

    public ValidatedUrl validate(String url) {
        if (url == null || url.length() > 2048) {
            throw new SsrfException("missing or oversized URL");
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= 0x20 || c == 0x7f || c == '\\') {
                throw new SsrfException("control character, space or backslash in URL");
            }
        }
        URI uri;
        try {
            uri = new URI(url).normalize();
        } catch (URISyntaxException e) {
            throw new SsrfException("malformed URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!schemes.contains(scheme)) {
            throw new SsrfException("scheme not allowed");
        }
        if (uri.getRawUserInfo() != null) {
            throw new SsrfException("credentials in URL are not allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new SsrfException("URL has no host");
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.indexOf('%') >= 0) {
            throw new SsrfException("IPv6 zone id not allowed");
        }
        if (!hosts.isEmpty() && !hostAllowed(host)) {
            throw new SsrfException("host not in allowlist");
        }
        int port = uri.getPort() == -1 ? ("https".equals(scheme) ? 443 : 80) : uri.getPort();
        if (!ports.contains(port)) {
            throw new SsrfException("port not allowed");
        }

        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            throw new SsrfException("host does not resolve");
        }
        if (addresses == null || addresses.length == 0) {
            throw new SsrfException("host does not resolve");
        }
        if (!allowPrivate) {
            for (InetAddress a : addresses) {
                if (isBlockedAddress(a)) {
                    throw new SsrfException("host resolves to a private, loopback or reserved address");
                }
            }
        }
        return new ValidatedUrl(uri, host, port, addresses);
    }

    public boolean isAllowed(String url) {
        try {
            validate(url);
            return true;
        } catch (SsrfException e) {
            return false;
        }
    }

    private boolean hostAllowed(String host) {
        for (String allowed : hosts) {
            if (allowed.startsWith("*.")) {
                String suffix = allowed.substring(1);
                if (host.endsWith(suffix) && host.length() > suffix.length()) {
                    return true;
                }
            } else if (allowed.equals(host)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True for loopback, private, link-local (incl. cloud metadata 169.254.169.254), CGNAT,
     * multicast, unspecified, documentation/benchmark ranges, IPv6 ULA, and IPv6 forms that
     * embed such an IPv4 address (mapped, NAT64, 6to4).
     */
    public static boolean isBlockedAddress(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true;
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            return isBlockedIpv4(b);
        }
        if (a instanceof Inet6Address) {
            int first = b[0] & 0xff;
            if ((first & 0xfe) == 0xfc) {
                return true; // fc00::/7 unique local
            }
            if (isZero(b, 0, 10) && (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) {
                return isBlockedIpv4(Arrays.copyOfRange(b, 12, 16)); // ::ffff:a.b.c.d
            }
            if (isZero(b, 0, 12)) {
                return true; // deprecated IPv4-compatible ::a.b.c.d
            }
            if (first == 0x00 && (b[1] & 0xff) == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b) {
                return isBlockedIpv4(Arrays.copyOfRange(b, 12, 16)); // 64:ff9b::/96 NAT64
            }
            if (first == 0x20 && (b[1] & 0xff) == 0x02) {
                return isBlockedIpv4(Arrays.copyOfRange(b, 2, 6)); // 2002::/16 6to4
            }
            if (first == 0x20 && (b[1] & 0xff) == 0x01 && (b[2] & 0xff) == 0x0d && (b[3] & 0xff) == 0xb8) {
                return true; // 2001:db8::/32 documentation
            }
        }
        return false;
    }

    private static boolean isBlockedIpv4(byte[] b) {
        int a0 = b[0] & 0xff;
        int a1 = b[1] & 0xff;
        int a2 = b[2] & 0xff;
        return a0 == 0                                   // 0.0.0.0/8
                || a0 == 10                              // 10/8
                || a0 == 127                             // loopback
                || (a0 == 100 && (a1 & 0xc0) == 64)      // 100.64/10 CGNAT
                || (a0 == 169 && a1 == 254)              // link-local, cloud metadata
                || (a0 == 172 && (a1 & 0xf0) == 16)      // 172.16/12
                || (a0 == 192 && a1 == 168)              // 192.168/16
                || (a0 == 192 && a1 == 0 && (a2 == 0 || a2 == 2)) // 192.0.0/24, 192.0.2/24
                || (a0 == 198 && (a1 & 0xfe) == 18)      // 198.18/15 benchmarking
                || (a0 == 198 && a1 == 51 && a2 == 100)  // documentation
                || (a0 == 203 && a1 == 0 && a2 == 113)   // documentation
                || a0 >= 224;                            // multicast, reserved, broadcast
    }

    private static boolean isZero(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static final class Builder {
        private final Set<String> schemes = new LinkedHashSet<String>(Arrays.asList("http", "https"));
        private final Set<String> hosts = new LinkedHashSet<String>();
        private final Set<Integer> ports = new LinkedHashSet<Integer>(Arrays.asList(80, 443));
        private boolean allowPrivate;
        private HostResolver resolver = new HostResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                return InetAddress.getAllByName(host);
            }
        };

        public Builder schemes(String... values) {
            schemes.clear();
            for (String v : values) {
                schemes.add(v.toLowerCase(Locale.ROOT));
            }
            return this;
        }

        /** Exact hosts or "*.example.com" suffixes. Empty means any public host. */
        public Builder allowHosts(String... values) {
            for (String v : values) {
                hosts.add(v.toLowerCase(Locale.ROOT));
            }
            return this;
        }

        public Builder ports(Integer... values) {
            ports.clear();
            ports.addAll(Arrays.asList(values));
            return this;
        }

        /** Only for trusted internal integrations; disables the private-range check. */
        public Builder allowPrivateNetworks(boolean value) {
            allowPrivate = value;
            return this;
        }

        public Builder resolver(HostResolver value) {
            resolver = value;
            return this;
        }

        public UrlGuard build() {
            return new UrlGuard(this);
        }
    }

    public static class SsrfException extends SecurityViolationException {
        private static final long serialVersionUID = 1L;

        public SsrfException(String message) {
            super(OwaspCategory.SSRF, message);
        }
    }
}
