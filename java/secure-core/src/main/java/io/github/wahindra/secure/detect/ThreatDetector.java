package io.github.wahindra.secure.detect;

public interface ThreatDetector {

    DetectionResult inspect(String input);

    /** Same as {@link #inspect(String)} but reuses an already normalized input. */
    DetectionResult inspect(NormalizedInput input);

    default boolean isMalicious(String input) {
        return inspect(input).isMalicious();
    }
}
