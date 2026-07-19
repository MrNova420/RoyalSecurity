# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within RoyalSecurity, please send an email to security@royalsecurity.dev. All security vulnerabilities will be promptly addressed.

Please include the following information in your report:

- Type of vulnerability (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Response Timeline

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours.
- **Assessment**: We will assess the vulnerability and determine its impact within 5 business days.
- **Fix**: We will develop and release a fix as soon as possible, depending on complexity.
- **Disclosure**: We will coordinate with you on the timing of public disclosure.

## Security Best Practices

When deploying RoyalSecurity in production:

- Run the agent service with SYSTEM privileges (required for PPL, TPM, and ETW access).
- Enable PPL (Protected Process Light) self-protection in the configuration.
- Use TPM-sealed encryption keys for sensitive data at rest.
- Enable the immutable audit log with hash-chain verification.
- Restrict network access to the REST API (port 9443) to authorized management networks only.
- Use mutual TLS (mTLS) for REST API authentication when possible.
- Regularly update threat intelligence feeds.
- Monitor the audit log for unauthorized configuration changes.
