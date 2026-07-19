package com.envcheck;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Stream;

/**
 * Walks a directory tree and scans text files for secrets using a set of
 * {@link SecretRule}s.
 */
public class Scanner {

    /** Directories that are never scanned. */
    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", "node_modules", "target", "build", "dist", ".idea",
            ".venv", "venv", "__pycache__", ".mvn", ".gradle"
    );

    /** File extensions that are skipped because they are typically binary. */
    private static final Set<String> BINARY_EXTENSIONS = Set.of(
            "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "jar", "class",
            "so", "dll", "exe", "woff", "woff2", "ttf", "eot", "bin", "dat"
    );

    /** Inline marker that suppresses a finding on that specific line. */
    private static final String IGNORE_MARKER = "envcheck:ignore";

    private final List<SecretRule> rules;

    public Scanner() {
        this(SecretRule.defaults());
    }

    public Scanner(List<SecretRule> rules) {
        this.rules = rules;
    }

    /**
     * Recursively scans the given root directory (or single file) and returns
     * all findings, sorted by file path then line number.
     */
    public List<Finding> scan(Path root) throws IOException {
        List<Finding> findings = new ArrayList<>();

        if (Files.isRegularFile(root)) {
            findings.addAll(scanFile(root));
            return findings;
        }

        try (Stream<Path> walk = Files.walk(root)) {
            List<Path> files = walk
                    .filter(Files::isRegularFile)
                    .filter(this::isNotIgnored)
                    .filter(this::isLikelyTextFile)
                    .toList();

            for (Path file : files) {
                findings.addAll(scanFile(file));
            }
        }

        return findings;
    }

    private boolean isNotIgnored(Path path) {
        for (Path part : path) {
            if (IGNORED_DIRS.contains(part.toString())) {
                return false;
            }
        }
        return true;
    }

    private boolean isLikelyTextFile(Path path) {
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot == -1) {
            return true; // no extension, e.g. Dockerfile, LICENSE - still worth scanning
        }
        String ext = name.substring(dot + 1).toLowerCase();
        return !BINARY_EXTENSIONS.contains(ext);
    }

    private List<Finding> scanFile(Path file) {
        List<Finding> findings = new ArrayList<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(file);
        } catch (MalformedInputException e) {
            return findings; // binary file that slipped through the extension filter
        } catch (IOException e) {
            return findings; // unreadable file (permissions, broken symlink, etc.)
        }

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.contains(IGNORE_MARKER)) {
                continue;
            }
            for (SecretRule rule : rules) {
                Matcher matcher = rule.pattern().matcher(line);
                if (matcher.find()) {
                    findings.add(new Finding(
                            file.toString(),
                            i + 1,
                            rule.name(),
                            redact(matcher.group())
                    ));
                }
            }
        }
        return findings;
    }

    /**
     * Redacts a matched secret so it is safe to print, keeping only a small
     * prefix/suffix for identification purposes.
     */
    static String redact(String match) {
        if (match.length() <= 8) {
            return "*".repeat(match.length());
        }
        String prefix = match.substring(0, 4);
        String suffix = match.substring(match.length() - 4);
        return prefix + "*".repeat(Math.max(4, match.length() - 8)) + suffix;
    }
}
