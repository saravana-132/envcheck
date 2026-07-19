package com.envcheck;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScannerTest {

    private Path writeFile(Path dir, String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
        return file;
    }

    @Test
    void detectsAwsAccessKey(@TempDir Path tempDir) throws IOException {
        writeFile(tempDir, "config.txt", "aws_key = AKIAABCDEFGHIJKLMNOP\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(tempDir);

        assertEquals(1, findings.size());
        assertEquals("AWS Access Key ID", findings.get(0).ruleName());
    }

    @Test
    void detectsPrivateKeyBlock(@TempDir Path tempDir) throws IOException {
        writeFile(tempDir, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(tempDir);

        assertTrue(findings.stream().anyMatch(f -> f.ruleName().equals("Private Key Block")));
    }

    @Test
    void detectsGenericApiKeyAssignment(@TempDir Path tempDir) throws IOException {
        writeFile(tempDir, ".env", "API_KEY=\"sk_test_51H8xyzABCDEFGHIJKLMNOP\"\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(tempDir);

        assertFalse(findings.isEmpty());
    }

    @Test
    void ignoresLineWithSuppressionMarker(@TempDir Path tempDir) throws IOException {
        writeFile(tempDir, "config.txt", "aws_key = AKIAABCDEFGHIJKLMNOP // envcheck:ignore\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(tempDir);

        assertTrue(findings.isEmpty());
    }

    @Test
    void skipsIgnoredDirectories(@TempDir Path tempDir) throws IOException {
        writeFile(tempDir, "node_modules/pkg/secret.txt", "AKIAABCDEFGHIJKLMNOP\n");
        writeFile(tempDir, ".git/config", "AKIAABCDEFGHIJKLMNOP\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(tempDir);

        assertTrue(findings.isEmpty());
    }

    @Test
    void cleanFileProducesNoFindings(@TempDir Path tempDir) throws IOException {
        writeFile(tempDir, "README.md", "This project has no secrets in it.\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(tempDir);

        assertTrue(findings.isEmpty());
    }

    @Test
    void redactionKeepsOnlyPrefixAndSuffix() {
        String redacted = Scanner.redact("AKIAABCDEFGHIJKLMNOP");
        assertTrue(redacted.startsWith("AKIA"));
        assertTrue(redacted.endsWith("MNOP"));
        assertTrue(redacted.contains("*"));
        assertFalse(redacted.contains("BCDEFGHIJKL"));
    }

    @Test
    void scanningSingleFileWorks(@TempDir Path tempDir) throws IOException {
        Path file = writeFile(tempDir, "lone.txt", "token: \"ghp_1234567890abcdef1234567890abcdef1234\"\n");

        Scanner scanner = new Scanner();
        List<Finding> findings = scanner.scan(file);

        assertFalse(findings.isEmpty());
    }
}
