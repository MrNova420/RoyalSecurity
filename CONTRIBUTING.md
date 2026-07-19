# Contributing to RoyalSecurity

Thank you for your interest in contributing to RoyalSecurity! This document provides guidelines and instructions for contributing.

## License

By contributing to RoyalSecurity, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE).

## Development Setup

### Prerequisites

- **Rust** 1.75+ (latest stable recommended)
- **Node.js** 18+ and npm
- **Windows** 10/11 or Windows Server 2019+ (required for Windows API bridges)
- **Git**

### Building

```bash
# Clone the repository
git clone https://github.com/MrNova420/RoyalSecurity.git
cd RoyalSecurity

# Build the Rust workspace
cargo build

# Build the frontend
cd royalsecurity-ui
npm install
npm run build
cd ..

# Build the release binary
cargo build --release
```

### Running Tests

```bash
# Run all workspace tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p royalsecurity-rule-engine
```

## Project Structure

```
RoyalSecurity/
├── src-tauri/              # Tauri application entry point & IPC commands
├── royalsecurity-ui/       # React frontend (TypeScript)
├── crates/
│   ├── core/               # EventBus, SecurityEngine, PPL, TPM, AuditLog
│   ├── common/             # Shared types across all crates
│   ├── windows-bridge/     # Windows API FFI (processes, network, registry)
│   ├── rule-engine/        # Sigma + YARA rule evaluation
│   ├── threat-intel/       # IOC feeds, matcher, updater
│   ├── siem/               # SIEM correlation engine
│   ├── siem-export/        # ECS, CEF, Syslog, Splunk HEC formatters
│   ├── state-store/        # Embedded database (redb)
│   ├── compliance/         # CIS/STIG/NIST compliance engine
│   ├── forensic-triage/    # EVTX, MFT, Prefetch, Registry parsers
│   ├── mitre-attack/       # 112 MITRE ATT&CK techniques
│   ├── stix-taxii/         # STIX 2.1 / TAXII 2.1 server
│   ├── rest-api/           # Axum REST API (port 9443)
│   ├── fleet-management/   # Multi-agent orchestration
│   ├── active-response/    # Automated containment & playbooks
│   ├── vuln-management/    # CVE database & CVSS v3.1 calculator
│   ├── crypto-vault/       # AES-256-GCM + TPM sealing
│   ├── collectors/         # 18 telemetry collectors (ETW, Sysmon, WFP, etc.)
│   ├── modules/            # 40+ defense/offense/privacy modules
│   └── ...
```

## Code Style

### Rust

- Follow standard `rustfmt` formatting.
- Use `tracing` for logging (not `log` or `println!`).
- All public APIs must have `#[derive(Serialize, Deserialize)]` where applicable.
- Error types should use `thiserror` for library crates and `anyhow` for application code.
- Prefer `Arc<RwLock<T>>` for shared mutable state.

### TypeScript/React

- Use functional components with hooks.
- All IPC calls go through `tauri-bridge.ts`.
- Use the `invokeCommand<T>()` wrapper for type-safe IPC.
- Maintain the dark theme UI consistency.

## Commit Messages

Use conventional commit format:

```
type(scope): description

feat(rule-engine): add regex pattern matching
fix(ipc): correct parameter name for block_ip
docs(readme): update architecture diagram
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes following the code style guidelines.
3. Add or update tests for any new functionality.
4. Ensure all tests pass: `cargo test --workspace`
5. Ensure the project builds: `cargo build --release`
6. Submit a pull request with a clear description of the changes.

## Reporting Issues

- Use the GitHub issue tracker.
- Include steps to reproduce for bug reports.
- Include your OS version, Rust version, and Node.js version.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Code of Conduct

Be respectful, inclusive, and constructive. We are building security software that protects people -- that mission starts with how we treat each other.
