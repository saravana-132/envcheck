package com.envcheck;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Command-line entry point for envcheck.
 *
 * Usage:
 *   java -jar envcheck.jar [path]
 *
 * Exit codes:
 *   0 - no secrets found
 *   1 - one or more potential secrets found
 *   2 - usage/runtime error
 */
public class Main {

    public static void main(String[] args) {
        if (args.length > 0 && (args[0].equals("-h") || args[0].equals("--help"))) {
            printUsage();
            System.exit(0);
        }

        String targetArg = args.length > 0 ? args[0] : ".";
        Path target = Path.of(targetArg);

        if (!target.toFile().exists()) {
            System.err.println("envcheck: path does not exist: " + targetArg);
            System.exit(2);
        }

        try {
            Scanner scanner = new Scanner();
            List<Finding> findings = scanner.scan(target);

            if (findings.isEmpty()) {
                System.out.println("envcheck: no secrets detected in '" + targetArg + "'");
                System.exit(0);
            }

            System.err.println("envcheck: found " + findings.size() + " potential secret(s):\n");
            for (Finding finding : findings) {
                System.err.println("  " + finding);
            }
            System.err.println("\nIf a finding is a false positive, add 'envcheck:ignore' as a comment on that line.");
            System.exit(1);

        } catch (IOException e) {
            System.err.println("envcheck: error scanning '" + targetArg + "': " + e.getMessage());
            System.exit(2);
        }
    }

    private static void printUsage() {
        System.out.println("""
                envcheck - scan a directory for accidentally committed secrets

                Usage:
                  java -jar envcheck.jar [path]

                Arguments:
                  path   File or directory to scan (default: current directory)

                Exit codes:
                  0   no secrets found
                  1   potential secret(s) found
                  2   usage or runtime error

                Suppress a false positive by adding 'envcheck:ignore' as a
                trailing comment on that specific line.
                """);
    }
}
