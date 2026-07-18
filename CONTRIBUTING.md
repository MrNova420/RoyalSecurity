# Contributing to RoyalSecurity

## Development Setup

### Prerequisites
- **Rust**: 1.75+ (install via rustup)
- **Node.js**: 18+ (for frontend)
- **Windows 10/11**: Required (Windows-only project)
- **Visual Studio Build Tools**: C++ workload for native dependencies

### Getting Started
```bash
git clone <repo-url>
cd RoyalSecurity
cargo build
cd royalsecurity-ui
npm install
npm run build
cargo test --workspace
```

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
`

### Naming Conventions
- Crates: oyalsecurity-{category}-{name}
- Modules: PascalCase structs, snake_case functions
- Files: snake_case
- Tests: #[cfg(test)] mod tests inside each file

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

## Commit Convention

`
<type>(<scope>): <description>
`

Types: feat, fix, docs, test, refactor, perf, chore

## Adding a New Module

1. Create crates/modules/defense/{name}/
2. Create Cargo.toml with standard deps
3. Create src/lib.rs with pub mod prelude;
4. Implement detection logic following existing patterns
5. Add unit tests (minimum 8)
6. Add to workspace Cargo.toml

## Security Guidelines

- Never log secrets
- Validate all input
- Use authenticated encryption (AES-GCM)
- Maintain hash chain audit log
- Follow principle of least privilege

## License

AGPL-3.0-or-later
