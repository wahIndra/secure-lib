package io.github.wahindra.secure.detect;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Runs every rule and reports each rule id at most once. */
public class RuleBasedDetector implements ThreatDetector {

    private final List<Rule> rules;

    public RuleBasedDetector(List<Rule> rules) {
        this.rules = Collections.unmodifiableList(new ArrayList<Rule>(rules));
    }

    @Override
    public DetectionResult inspect(String input) {
        if (input == null || input.isEmpty()) {
            return DetectionResult.clean();
        }
        return inspect(NormalizedInput.of(input));
    }

    @Override
    public DetectionResult inspect(NormalizedInput input) {
        List<Finding> findings = new ArrayList<Finding>();
        for (Rule rule : rules) {
            if (rule.matches(input)) {
                findings.add(rule.toFinding());
            }
        }
        return DetectionResult.of(findings);
    }

    public List<Rule> getRules() { return rules; }
}
