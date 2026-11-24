package io.github.wahindra.secure.web;

import java.util.Map;

/**
 * The parts of an HTTP request that {@link SecurityFilterEngine} needs, independent of the web
 * framework. Servlet, Spring and other adapters implement it.
 */
public interface RequestView {

    String method();

    /** The raw (undecoded) request URI without the query string, e.g. {@code getRequestURI()}. */
    String rawPath();

    String remoteAddress();

    /** One header value, matched case-insensitively, or {@code null}. */
    String header(String name);

    /** All headers (first value of each). */
    Map<String, String> headers();

    /** Query and form parameters. Called after the JSON body was read, so it never consumes it. */
    Map<String, String[]> parameters();

    /** {@code Content-Type} header, or {@code null}. */
    default String contentType() {
        return header("Content-Type");
    }

    /** {@code Content-Length}, or -1 when unknown (chunked). */
    default long contentLength() {
        String v = header("Content-Length");
        try {
            return v == null ? -1 : Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
