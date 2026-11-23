package io.github.wahindra.secure.errors;

import io.github.wahindra.secure.logging.LogSanitizer;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Mishandling of Exceptional Conditions: log the full detail server-side under an incident id,
 * return only a generic message plus that id to the client. Never echo stack traces, SQL
 * errors or framework versions in responses.
 *
 * <pre>
 * } catch (RuntimeException e) {
 *     String id = SafeErrors.log(LOG, e, "order checkout failed");
 *     return ResponseEntity.status(500).body(SafeErrors.publicBody(id));
 * }
 * </pre>
 */
public final class SafeErrors {

    public static final String PUBLIC_MESSAGE = "An unexpected error occurred.";

    private SafeErrors() {
    }

    public static String newIncidentId() {
        return UUID.randomUUID().toString();
    }

    /** Logs the exception with a fresh incident id and returns the id. */
    public static String log(Logger logger, Throwable error, String context) {
        String id = newIncidentId();
        StringWriter trace = new StringWriter();
        error.printStackTrace(new PrintWriter(trace));
        logger.log(Level.SEVERE, "incident=" + id + " " + LogSanitizer.sanitize(context)
                + " " + LogSanitizer.sanitize(trace.toString(), 8000));
        return id;
    }

    /** JSON body safe to return to any client. */
    public static String publicBody(String incidentId) {
        return "{\"error\":\"" + PUBLIC_MESSAGE + "\",\"incidentId\":\"" + incidentId.replaceAll("[^A-Za-z0-9-]", "") + "\"}";
    }
}
