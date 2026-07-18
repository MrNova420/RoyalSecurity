# RoyalSecurity

## Overview
Military-grade, enterprise, production-grade all-in-one cybersecurity platform for Windows. Combines EDR, NGAV, XDR, SIEM, HIPS, DLP, UEBA, ASR, and 40+ security capabilities into a single lightweight 24/7 local agent with a modern Tauri 2 + React 18 UI.

## Architecture
- **Backend**: Rust (Tokio async runtime, 80+ crate workspace)
- **UI**: Tauri 2 + React 18 + TypeScript + TailwindCSS
- **Database**: redb embedded database (9 tables)
- **Event System**: tokio::broadcast (100k capacity)
- **Crypto**: AES-256-GCM, ChaCha20-Poly1305, SHA-256 hash chain
- **Installer**: Inno Setup

## Performance Targets

| Metric | Target |
|--------|--------|
| RAM (idle) | ≤80MB |
| CPU (idle) | ≤0.3% |
| Event throughput | 100k+ events/sec |
| P99 latency | <5ms |
| Binary size | ~6MB |

## Security Model
- SYSTEM service + user UI separation via IPC
- PPL (Protected Process Light) self-protection
- TPM-sealed encryption keys
- Immutable SHA-256 hash-chained audit log
- Zero-trust local-only architecture

## Implemented Modules (15 with full detection logic + 260 unit tests)

### Core Detection

| Module | Description | MITRE Techniques |
|--------|-------------|------------------|
| **EDR** | Process tree tracking, credential dump, process injection, encoded PowerShell, LOLBin detection | T1003, T1055, T1059.001, T1218 |
| **Behavior** | Runtime behavioral analysis, IOA detection, process chain analysis | Multiple |
| **AV** | NGAV engine: YARA rules, entropy analysis, reputation cache, signature scanning | Multiple |
| **Injection** | DLL injection, process hollowing, APC injection, reflective loading, module stomping | T1055, T1055.012, T1055.013 |
| **Fileless** | PowerShell obfuscation, AMSI bypass, script block analysis, certutil/mshta abuse | T1059.001, T1059.005, T1218 |
| **Ransomware** | Mass file modification/rename detection, VSS rollback engine | T1486 |
| **Credential** | LSASS protection, token theft detection | T1003 |
| **Persistence** | 12 registry/service/scheduled task checks | T1547 |

### Exploit & Hardening

| Module | Description |
|--------|-------------|
| **Exploit** | DEP/ASLR/CFG bypass, ROP chain detection, heap spray, sandbox escape |
| **ASR** | 12 Attack Surface Reduction rules (Office, scripts, credentials, WMI) |
| **Hardening** | 24 CIS benchmark checks, compliance scoring, remediation generation |
| **Memory** | Inline hooks, IAT hooks, detours, code caves, module tampering detection |

### Network Analysis

| Module | Description |
|--------|-------------|
| **Beacon** | C2 beacon detection, jitter analysis, DNS tunnel, dead drops |
| **DGA** | Domain Generation Algorithm detection, entropy analysis, n-gram stats |
| **DNS** | DNS monitoring, typosquatting, blocklist/allowlist, tunnel detection |
| **LOLBin** | 25 Living-off-the-Land Binary detection rules |

### Advanced Monitoring

| Module | Description |
|--------|-------------|
| **UEBA** | User behavior analytics, baseline deviation, risk scoring, insider threat |
| **Firewall** | Host-based firewall, CIDR matching, rate limiting, 7 default rules |
| **Network** | Flow tracking, port scan detection, protocol anomalies, exfil detection |

## Project Structure

```
RoyalSecurity/
├── Cargo.toml                 # Workspace root (80+ crates)
├── src-tauri/                 # Tauri 2 backend
│   └── src/main.rs           # 20 IPC commands
├── royalsecurity-ui/          # React 18 frontend
│   └── src/pages/            # 8 UI pages
├── crates/
│   ├── core/                  # Event bus, module trait, config, crypto, audit
│   ├── common/                # 54 event types, 57 MITRE techniques, errors
│   ├── state-store/           # redb database (9 tables)
│   ├── rule-engine/           # Sigma rules + custom DSL
│   ├── threat-intel/          # STIX/IOC feed management
│   └── modules/defense/       # 15 implemented defense modules
├── config/default.toml        # Default configuration
└── installer/                 # Inno Setup installer
```

## Installation

### Prerequisites
- Windows 10/11 (64-bit)
- Rust 1.75+ (for building from source)
- Node.js 18+ (for building the UI)

### Build from Source

```bash
# Clone the repository
git clone <repo-url>
cd RoyalSecurity

# Build the release binary
cargo build --release

# Build the frontend
cd royalsecurity-ui
npm install
npm run build
cd ..

# Create installer (requires Inno Setup)
installer\build-installer.bat
```

### Run

```bash
# Development
cargo run --release

# Or use the pre-built binary
RoyalSecurity.exe
```

## Configuration

Edit `config/default.toml` to customize:

```toml
[general]
app_name = "RoyalSecurity"
log_level = "info"

[detection]
real_time_protection = true
behavior_analysis = true
ransomware_protection = true
```

## IPC API (20 commands)

The Tauri backend exposes these commands to the React UI:

| Command | Description |
|---------|-------------|
| `get_config` | Get current configuration |
| `update_config` | Update configuration |
| `get_module_health` | Get all module health status |
| `get_events` | Query security events |
| `get_threats` | Get detected threats |
| `search_iocs` | Search IOC database |
| `compile_sigma_rule` | Compile Sigma rule to executable |
| `encrypt_data` / `decrypt_data` | AES-256-GCM encryption |
| `get_audit_log` | Query immutable audit log |
| `get_mitre_coverage` | Get MITRE ATT&CK coverage map |
| `get_compliance_status` | Get compliance check results |
| `get_system_info` | Get system information |
| `list_processes` | List running processes |
| `get_network_connections` | Get active network connections |
| `get_alert_stats` | Get alert statistics |
| `update_threat_intel` | Trigger threat intel feed update |

## UI Pages (React 18 + TailwindCSS)

1. **Dashboard** - Overview with charts, alerts, system status
2. **Threats** - Active threat list with details
3. **Processes** - Process monitor with tree view
4. **Network** - Network connections and flow analysis
5. **Rules** - Sigma/DSL rule editor
6. **Compliance** - CIS/NIST/STIG compliance dashboard
7. **Audit Log** - Immutable audit trail viewer
8. **Settings** - Configuration management

## License

AGPL-3.0-or-later

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
