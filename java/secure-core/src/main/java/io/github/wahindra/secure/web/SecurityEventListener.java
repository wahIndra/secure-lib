package io.github.wahindra.secure.web;

/**
 * Receives {@link SecurityEvent}s, for example to forward them to a SIEM, Slack or metrics.
 * Called on the request thread: keep it fast, or hand events to a queue. Exceptions thrown by a
 * listener are caught and logged; they never affect the request.
 *
 * <pre>
 * SecurityEventListener toSiem = event -&gt; siemQueue.offer(event.toJson());
 * </pre>
 */
public interface SecurityEventListener {

    void onEvent(SecurityEvent event);
}
