# envcheck

A lightweight, zero-dependency Java CLI that scans a directory tree for accidentally committed secrets — API keys, AWS credentials, private keys, tokens — **before you push them to a remote repository.**

[![CI](https://github.com/saravana-132/envcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/saravana-132/envcheck/actions/workflows/ci.yml)
![Java](https://img.shields.io/badge/Java-17%2B-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

## Why

Every engineer has committed a secret by accident at some point — an `.env` file, an AWS key hardcoded "just for testing," a private key copy-pasted into a config. `envcheck` catches these before they leave your machine, either as a manual check, a git pre-commit hook, or a CI gate.

## Features

- Detects AWS keys, Google API keys, GitHub tokens, Slack tokens, Stripe live keys, private key blocks, JWTs, and generic `key=`/`secret=`/`password=` assignments
- Redacts findings in output — never prints the full secret, only a masked preview
- Skips `.git`, `node_modules`, `target`, `build`, `dist`, and other noise directories automatically
- Inline suppression for false positives via an `envcheck:ignore` comment
- Single dependency-free fat JAR — drop it anywhere and run it
- Exit codes designed for scripting: `0` clean, `1` findings, `2` error
- Ships with a sample git pre-commit hook and a GitHub Actions CI example

## Installation

Requires Java 17+.

```bash
git clone https://github.com/saravana-132/envcheck.git
cd envcheck
mvn package
```

This produces `target/envcheck.jar`.

## Usage

```bash
# scan the current directory
java -jar target/envcheck.jar

# scan a specific path
java -jar target/envcheck.jar /path/to/project

# scan a single file
java -jar target/envcheck.jar .env
```

### Example output

```
$ java -jar target/envcheck.jar .
envcheck: found 2 potential secret(s):

  ./config.txt:14  [AWS Access Key ID]  AKIA************MNOP
  ./.env:3          [Generic API Key/Secret Assignment]  API_*********************NOP"

If a finding is a false positive, add 'envcheck:ignore' as a comment on that line.
```

### Suppressing a false positive

Add `envcheck:ignore` anywhere on the offending line:

```
TEST_KEY = "AKIAABCDEFGHIJKLMNOP"  // envcheck:ignore
```

## Using it as a pre-commit hook

```bash
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The commit will be blocked if `envcheck` detects a likely secret in the working tree.

## Using it in CI

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a working example. The key step:

```yaml
- name: Scan for secrets
  run: java -jar target/envcheck.jar .
```

A non-zero exit code fails the build.

## Detection rules

| Rule | What it catches |
|---|---|
| AWS Access Key ID | `AKIA...` style keys |
| AWS Secret Access Key | `aws_secret_key = "..."` style assignments |
| Google API Key | `AIza...` keys |
| GitHub Token | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens |
| Slack Token | `xoxb-`, `xoxp-`, etc. |
| Stripe Live Secret Key | `sk_live_...` |
| Private Key Block | PEM-formatted RSA/EC/DSA/OpenSSH/PGP private keys |
| Generic JWT | Three-segment base64url JWT structure |
| Generic key/secret/token/password assignment | Catch-all for `key = "..."` style patterns |

Rules are intentionally conservative to minimize false positives — this is a first line of defense, not a replacement for a secrets manager (Vault, AWS Secrets Manager, 1Password, etc.) or a full-featured scanner like `gitleaks`/`trufflehog` for historical git-log scanning.

## Running the tests

```bash
mvn test
```

Tests cover each detection rule, directory-skipping behavior, the inline ignore marker, and the redaction logic.

## Project structure

```
envcheck/
├── src/main/java/com/envcheck/
│   ├── Main.java         # CLI entry point
│   ├── Scanner.java      # Directory walk + file scanning
│   ├── SecretRule.java   # Rule definitions
│   └── Finding.java      # A single detection result
├── src/test/java/com/envcheck/
│   └── ScannerTest.java
├── scripts/pre-commit    # Sample git hook
└── .github/workflows/ci.yml
```

## Roadmap / ideas for contributions

- Config file support for custom rules and ignored paths (`.envcheckrc`)
- `--json` output mode for machine consumption
- Entropy-based detection for high-entropy strings not matching a known pattern
- Scan git history, not just the working tree

## License

MIT — see [LICENSE](LICENSE).
