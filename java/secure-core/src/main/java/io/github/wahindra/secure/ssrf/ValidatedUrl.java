package io.github.wahindra.secure.ssrf;

import java.net.InetAddress;
import java.net.URI;

public final class ValidatedUrl {

    private final URI uri;
    private final String host;
    private final int port;
    private final InetAddress[] addresses;

    ValidatedUrl(URI uri, String host, int port, InetAddress[] addresses) {
        this.uri = uri;
        this.host = host;
        this.port = port;
        this.addresses = addresses.clone();
    }

    public URI getUri() { return uri; }
    public String getHost() { return host; }
    public int getPort() { return port; }

    /** The checked addresses. Connect to one of these, not to a fresh DNS lookup of the host. */
    public InetAddress[] getAddresses() { return addresses.clone(); }
}
