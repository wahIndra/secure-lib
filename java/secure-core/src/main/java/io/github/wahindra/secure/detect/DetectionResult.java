package io.github.wahindra.secure.detect;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class DetectionResult {
    /** One HIGH finding, or two MEDIUM findings, marks input as malicious. */
    public static final int MALICIOUS_SCORE = 6;

    private static final DetectionResult CLEAN = new DetectionResult(Collections.<Finding>emptyList());

    private final List<Finding> findings;
    private final int score;

    private DetectionResult(List<Finding> findings) {
        this.findings = Collections.unmodifiableList(findings);
        int s = 0;
        for (Finding f : findings) {
            s += f.getSeverity().score();
        }
        this.score = s;
    }

    public static DetectionResult clean() { return CLEAN; }

    public static DetectionResult of(List<Finding> findings) {
        return findings.isEmpty() ? CLEAN : new DetectionResult(new ArrayList<Finding>(findings));
    }

    public static DetectionResult merge(List<DetectionResult> results) {
        List<Finding> all = new ArrayList<Finding>();
        for (DetectionResult r : results) {
            all.addAll(r.findings);
        }
        return of(all);
    }

    public List<Finding> getFindings() { return findings; }
    public int getScore() { return score; }
    public boolean isMalicious() { return score >= MALICIOUS_SCORE; }
    public boolean isSuspicious() { return !findings.isEmpty(); }

    @Override
    public String toString() {
        return "DetectionResult{score=" + score + ", findings=" + findings + "}";
    }
}
