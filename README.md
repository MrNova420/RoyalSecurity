# RoyalSecurity

![License](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Tests](https://img.shields.io/badge/tests-1200%2B-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows_10%2F11-lightgrey)
![Version](https://img.shields.io/badge/version-0.1.0-orange)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

**Military-grade, all-in-one cybersecurity platform for Windows.**

EDR, XDR, SIEM, NGAV, HIPS, DLP, UEBA, firewall, threat intelligence, and 40+ security capabilities in a single lightweight 24/7 local agent with a modern Tauri 2 + React UI.

> **Disclaimer**: This software is provided as-is for educational and defensive purposes. Use responsibly and in compliance with all applicable laws.

---

## Features

| Category | Capabilities |
|----------|-------------|
| **EDR/XDR** | Process tree tracking, injection detection (DLL, hollowing, APC), credential dump detection, LOLBin detection, fileless malware analysis |
| **Ransomware** | Mass file modification/rename detection, VSS rollback engine, ransom note detection |
| **Network Security** | DNS monitoring, C2 beacon detection, DGA analysis, port scan detection, host-based firewall, TLS inspection |
| **Threat Intelligence** | 15-source aggregation (VirusTotal, AlienVault, AbuseCh, CISA, MITRE, etc.), hourly updates, STIX 2.1 export, IOC matching |
| **Detection Rules** | 46+ YARA rules (malware families, techniques, script abuse) + 20+ Sigma rules for Windows attack detection |
| **Privacy** | VPN/Tor integration, tracker blocking, metadata removal, anti-fingerprinting |
| **Hardening** | CIS benchmark checks, 12 ASR rules, PPL self-protection, TPM-sealed encryption |
| **Audit** | SHA3-256 hash-chained immutable log, compliance reporting, tamper detection |
| **Memory Protection** | Inline hooks, IAT hooks, detours, code caves, module tampering detection |
| **Behavioral Analysis** | Runtime IOA detection, process chain analysis, UEBA risk scoring |

---

## Quick Install

### Option 1: Download Release (Recommended)

1. Download `RoyalSecurity-Setup-0.1.0.exe` from [Releases](https://github.com/kayde/RoyalSecurity/releases/latest)
2. **Run as Administrator**
3. Follow the setup wizard
4. That's it -- the agent starts automatically and begins protecting your system

### Option 2: Build from Source

```bash
# Prerequisites: Rust 1.75+, Node.js 18+, Windows 10/11 x64
git clone https://github.com/kayde/RoyalSecurity.git
cd RoyalSecurity

# Build backend
cargo build --release

# Build frontend
cd royalsecurity-ui
npm install
npm run build
cd ..

# The binary is at: target/release/royalsecurity.exe
```

### Option 3: Create Installer

```powershell
# Requires Inno Setup 6+ installed
installer\build-installer.bat
# Output: installer/output/RoyalSecurity-Setup-0.1.0.exe
```

---

## First Launch

On first launch, the **Setup Wizard** guides you through:

1. **System Scan** -- Detects OS, TPM, PPL support, hardware info
2. **Module Selection** -- Enable/disable EDR, Ransomware, Network, Threat Intel, Firewall, DLP, Privacy
3. **Scan Schedule** -- Configure real-time, quick, and full scan intervals
4. **Threat Intel Feeds** -- Select which intelligence sources to enable

---

## Architecture

```
RoyalSecurity/
├── Cargo.toml                    # Workspace root (80+ crates)
├── src-tauri/                    # Tauri 2 backend (35 IPC commands)
│   └── src/main.rs              # Application entry point
├── royalsecurity-ui/             # React 19 + TypeScript + TailwindCSS
│   └── src/pages/               # 8 UI pages + Setup Wizard
├── crates/
│   ├── core/                     # EventBus, SecurityEngine, config, crypto, PPL, TPM
│   ├── common/                   # 54 event types, 57 MITRE techniques
│   ├── state-store/              # redb embedded database
│   ├── rule-engine/              # YARA (46+ rules) + Sigma (20+ rules) + DSL
│   ├── threat-intel/             # 15-source aggregator, IOC store, STIX 2.1
│   ├── audit-log/                # SHA3-256 hash chain, ring buffer
│   ├── crypto-vault/             # AES-256-GCM, TPM sealing
│   ├── agent-service/            # Windows SCM service
│   ├── windows-bridge/           # Win32 API: process, network, registry, affinity
│   ├── compliance/               # CIS/STIG benchmark engine
│   ├── collectors/               # 20 data collectors (DNS, ETW, WFP, WMI, etc.)
│   ├── modules/defense/          # 15 defense modules with 987 tests
│   └── network-stack/            # DNS proxy, TLS inspection, Tor, WireGuard
├── config/default.toml           # Default configuration
├── installer/                    # Inno Setup installer script
└── rules/                        # YARA and Sigma rule files
```

---

## Performance

| Metric | Target | Status |
|--------|--------|--------|
| RAM (idle) | ≤80MB | Achieved |
| CPU (idle) | ≤0.3% | Achieved |
| Event throughput | 100k+ events/sec | Lock-free ring buffer |
| P99 latency | <5ms | Arena allocator + SPSC fast path |
| Binary size | ~6MB | Stripped release build |
| Test coverage | 1,200+ tests | 0 failures |

---

## Security Model

- **SYSTEM service** + user UI separation via Tauri IPC
- **PPL** (Protected Process Light) self-protection
- **TPM-sealed** encryption keys
- **SHA3-256** hash-chained immutable audit log
- **Zero-trust** local-only architecture (no cloud dependency)

---

## Configuration

Edit `config/default.toml` or use the Settings page in the UI:

```toml
[general]
app_name = "RoyalSecurity"
log_level = "info"

[detection]
real_time_protection = true
behavior_analysis = true
ransomware_protection = true

[threat_intel]
update_interval_minutes = 15
auto_update = true

[privacy]
tracker_blocking = true
metadata_removal = true
```

---

## IPC API (35 commands)

| Command | Description |
|---------|-------------|
| `get_system_info` | System information |
| `get_process_list` | Running processes |
| `get_network_connections` | Active connections |
| `get_alert_stats` | Alert statistics |
| `get_mitre_coverage` | MITRE ATT&CK map |
| `get_compliance_status` | Compliance score |
| `get_audit_log` | Immutable audit log |
| `get_engine_stats` | Engine metrics |
| `get_detection_rules` | Rule counts |
| `trigger_scan` | Start a scan |
| `trigger_threat_intel_update` | Force intel update |
| `evaluate_event` | Evaluate a security event |
| `add_yara_rule` / `add_sigma_rule` | Add detection rules |
| `encrypt_data` / `decrypt_data` | AES-256-GCM encryption |
| `update_config` | Update configuration |

---

## UI Pages

1. **Dashboard** -- Overview with charts, alerts, MITRE coverage
2. **Threats** -- Active threat list with severity and status
3. **Processes** -- Process monitor with detail view
4. **Network** -- Connection monitor with flagging
5. **Rules** -- YARA/Sigma rule management
6. **Compliance** -- CIS/STIG benchmark results
7. **Audit Log** -- Immutable, hash-chained event log
8. **Settings** -- Configuration and module toggles

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

---

## License

AGPL-3.0-or-later -- See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with [Tauri](https://tauri.app), [React](https://react.dev), [TailwindCSS](https://tailwindcss.com), and [Rust](https://rust-lang.org).
Detection rules inspired by [Sigma](https://github.com/SigmaHQ/sigma), [YARA](https://virustotal.github.io/yara/), and [MITRE ATT&CK](https://attack.mitre.org/).
