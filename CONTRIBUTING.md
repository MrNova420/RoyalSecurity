# Contributing to RoyalSecurity

Thank you for considering contributing to RoyalSecurity! This document provides guidelines for contributing to the project.

## Development Prerequisites

- **Rust**: 1.75+ (install via [rustup](https://rustup.rs/))
- **Node.js**: 18+ (for frontend/UI development)
- **Windows 10/11**: Required (this is a Windows-only security product)
- **Visual Studio Build Tools**: C++ workload for native dependencies
- **Inno Setup 6**: For building installers (optional)

## Getting Started

1. Fork the repository
2. Clone your fork:
   `ash
   git clone https://github.com/your-username/RoyalSecurity.git
   cd RoyalSecurity
   `
3. Create a feature branch:
   `ash
   git checkout -b feature/my-feature
   `
4. Make your changes
5. Run tests:
   `ash
   cargo test --workspace
   `
6. Commit your changes following the commit convention below
7. Push to your fork and submit a Pull Request

## Project Structure

`
crates/
  common/             # Shared types, errors, constants
  core/               # Core engine (bus, module trait, config, crypto, audit)
  state-store/        # redb database layer
  rule-engine/        # Sigma rules + DSL
  threat-intel/       # IOC feed management
  modules/defense/    # 15 defensive security modules
  collectors/         # Data collection (ETW, WFP, etc.)
  network-stack/      # Network modules (firewall, DNS, VPN)
royalsecurity-ui/     # Frontend (React/TypeScript)
browser-extension/    # Browser extension for web protection
`

## Code Style

- Use cargo fmt before commit
- Run cargo clippy -- -D warnings before commit
- Prefer 	hiserror for error types
- Use 	racing macros for logging (not println!)
- Use serde derives for all data structures

## Testing

- Every module must have unit tests
- Use descriptive test names
- Test both positive and negative cases
- Run cargo test --workspace before committing
- Aim for comprehensive coverage of detection logic

## Commit Convention

`
<type>(<scope>): <description>
`

Types: eat, ix, docs, 	est, efactor, perf, chore

Examples:
- eat(defense): add process injection detection
- ix(collector): resolve ETW session leak
- docs: update architecture documentation

## Adding a New Module

1. Create crates/modules/defense/{name}/
2. Create Cargo.toml with standard dependencies
3. Create src/lib.rs with pub mod prelude;
4. Implement detection logic following existing patterns
5. Add unit tests (minimum 8)
6. Add to workspace Cargo.toml

## Pull Request Process

1. Update documentation if your change affects public APIs
2. Add or update tests for new functionality
3. Ensure all CI checks pass
4. Request review from maintainers
5. Address review feedback promptly
6. Once approved, a maintainer will merge your PR

## Issue Templates

### Bug Report
- Describe the issue clearly
- Include steps to reproduce
- Provide environment details (OS version, Rust version)
- Include relevant log files (if safe to share)

### Feature Request
- Describe the feature and its use case
- Explain why it would benefit the project
- Consider security implications

### Security Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

If you discover a security issue, please report it responsibly:

1. Email: security@royalsecurity.dev (or use private vulnerability reporting)
2. Include a detailed description of the vulnerability
3. Provide steps to reproduce if possible
4. Allow reasonable time for a fix before public disclosure

We take security issues seriously and will respond within 48 hours.

## Security Guidelines

- Never log secrets or credentials
- Validate all external input
- Use authenticated encryption (AES-GCM) for sensitive data
- Maintain hash chain audit log integrity
- Follow principle of least privilege
- Report vulnerabilities responsibly (see above)

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0-or-later license.
