package com.envcheck;

/**
 * Represents a single potential secret detected in a file.
 *
 * @param filePath the path to the file where the secret was found
 * @param lineNumber the 1-based line number of the match
 * @param ruleName the name of the rule/pattern that matched
 * @param redactedSnippet a redacted preview of the matching line, safe to print
 */
public record Finding(String filePath, int lineNumber, String ruleName, String redactedSnippet) {

    @Override
    public String toString() {
        return String.format("%s:%d  [%s]  %s", filePath, lineNumber, ruleName, redactedSnippet);
    }
}
