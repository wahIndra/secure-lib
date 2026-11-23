package io.github.wahindra.secure;

import io.github.wahindra.secure.detect.DetectionResult;
import io.github.wahindra.secure.detect.NormalizedInput;
import io.github.wahindra.secure.detect.ThreatDetector;
import io.github.wahindra.secure.injection.CommandInjectionDetector;
import io.github.wahindra.secure.injection.SqlInjectionDetector;
import io.github.wahindra.secure.injection.XssDetector;
import io.github.wahindra.secure.path.PathTraversalDetector;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Runs several detectors over one input, normalizing it only once.
 *
 * <pre>
 * DetectionResult r = InputInspector.defaults().inspect(value);
 * if (r.isMalicious()) { ... reject, log r.getFindings() ... }
 * </pre>
 */
public final class InputInspector {

    private static final InputInspector DEFAULT = new InputInspector(Arrays.<ThreatDetector>asList(
            SqlInjectionDetector.defaults(),
            XssDetector.defaults(),
            CommandInjectionDetector.defaults(),
            PathTraversalDetector.defaults()));

    private final List<ThreatDetector> detectors;

    public InputInspector(List<ThreatDetector> detectors) {
        this.detectors = Collections.unmodifiableList(new ArrayList<ThreatDetector>(detectors));
    }

    /** SQL injection, XSS, command/JNDI injection and path traversal. */
    public static InputInspector defaults() {
        return DEFAULT;
    }

    public DetectionResult inspect(String input) {
        if (input == null || input.isEmpty()) {
            return DetectionResult.clean();
        }
        NormalizedInput n = NormalizedInput.of(input);
        List<DetectionResult> results = new ArrayList<DetectionResult>(detectors.size());
        for (ThreatDetector d : detectors) {
            results.add(d.inspect(n));
        }
        return DetectionResult.merge(results);
    }

    public boolean isMalicious(String input) {
        return inspect(input).isMalicious();
    }

    public List<ThreatDetector> getDetectors() {
        return detectors;
    }
}
