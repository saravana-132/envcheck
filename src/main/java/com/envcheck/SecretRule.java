package com.envcheck;

import java.util.List;
import java.util.regex.Pattern;

/**
 * A named regex rule used to detect a specific class of secret.
 */
public record SecretRule(String name, Pattern pattern) {

    public static SecretRule of(String name, String regex) {
        return new SecretRule(name, Pattern.compile(regex));
    }

    /**
     * The default set of built-in detection rules. Kept intentionally small
     * and high-signal to minimize false positives.
     */
    public static List<SecretRule> defaults() {
        return List.of(
                of("AWS Access Key ID", "AKIA[0-9A-Z]{16}"),
                of("AWS Secret Access Key", "(?i)aws(.{0,20})?(secret|key)(.{0,20})?[:=]\\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
                of("Google API Key", "AIza[0-9A-Za-z\\-_]{35}"),
                of("GitHub Token", "gh[pousr]_[A-Za-z0-9]{36}"),
                of("Slack Token", "xox[baprs]-[0-9a-zA-Z-]{10,}"),
                of("Stripe Live Secret Key", "sk_live_[0-9a-zA-Z]{16,}"),
                of("Private Key Block", "-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
                of("Generic JWT", "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"),
                of("Generic API Key/Secret Assignment",
                        "(?i)(api[_-]?key|secret|token|password|passwd|pwd)\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{12,}['\"]")
        );
    }
}
