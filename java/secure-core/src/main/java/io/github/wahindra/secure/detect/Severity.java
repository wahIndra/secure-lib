package io.github.wahindra.secure.detect;

public enum Severity {
    LOW(1), MEDIUM(3), HIGH(10);

    private final int score;

    Severity(int score) { this.score = score; }

    public int score() { return score; }
}
