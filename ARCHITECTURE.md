# RoyalSecurity Architecture

## System Architecture Overview
RoyalSecurity follows a layered architecture with clear separation of concerns:

`
+---------------------------------------------+
¦              React 18 UI (Tauri)            ¦
¦  Dashboard | Threats | Processes | Network  ¦
¦  Rules | Compliance | Audit Log | Settings  ¦
+---------------------------------------------¦
¦           Tauri 2 IPC Bridge (20 cmds)      ¦
+---------------------------------------------¦
¦              Core Engine                     ¦
¦  EventBus | ModuleRegistry | CryptoVault    ¦
¦  AuditLog | StateStore | RuleEngine         ¦
+---------------------------------------------¦
¦           Security Modules (15)             ¦
¦  EDR | AV | Behavior | Injection | Fileless ¦
¦  Ransomware | Credential | Persistence      ¦
¦  Exploit | ASR | Hardening | Memory         ¦
¦  Beacon | DGA | DNS | LOLBin | UEBA         ¦
¦  Firewall | Network                         ¦
+---------------------------------------------¦
¦           Data Collectors                    ¦
¦  ETW | Registry | WFP | Sysmon | WMI       ¦
+---------------------------------------------¦
¦           Windows Kernel / OS               ¦
+---------------------------------------------+
`

## Core Components

### EventBus (crates/core/src/bus.rs)
- **Technology**: 	okio::sync::broadcast channel
- **Capacity**: 100,000 events
- **Pattern**: Pub-sub, async, multi-subscriber
- **Event type**: SecurityEvent enum (Process, File, Network, Dns, Registry, Service, Memory, Thread)

### ModuleRegistry (crates/core/src/registry.rs)
- **Purpose**: Manages lifecycle of security modules
- **Pattern**: Plugin architecture with SecurityModule trait
- **Lifecycle**: Initialize ? Start ? Running ? Stop
- **Health**: Heartbeat monitoring, error counting, EPS tracking

### CryptoVault (crates/core/src/crypto.rs)
- **Algorithms**: AES-256-GCM (primary), ChaCha20-Poly1305 (fallback)
- **Key Management**: Derivation from master key, per-module keys
- **Operations**: Encrypt/decrypt with authenticated encryption

### AuditLog (crates/core/src/audit.rs)
- **Integrity**: SHA-256 hash chain (each entry hashes previous)
- **Immutability**: Cannot modify without breaking chain
- **Storage**: Append-only, file-backed

### StateStore (crates/state-store/src/store.rs)
- **Database**: redb (Rust-native, ACID, zero-copy reads)
- **Tables**: events, processes, network, threats, audit, rules, iocs, config, modules
- **Pattern**: Embedded, no separate server process

### RuleEngine (crates/rule-engine/)
- **Sigma**: YAML-based detection rules (industry standard)
- **DSL**: Custom rule language for complex conditions
- **Pattern matching**: Contains, Regex, Gt, Lt, Gte, Lte, StartsWith, EndsWith, Exists

## Data Flow

### Event Processing Pipeline
`
Windows Kernel (ETW/WFP/Sysmon)
    ?
Collectors (raw events)
    ?
EventBus (broadcast)
    ?
+------------------------------+
¦  Module Processors (parallel) ¦
¦  +- EDR                      ¦
¦  +- Behavior                 ¦
¦  +- AV                       ¦
¦  +- Injection                ¦
¦  +- Fileless                 ¦
¦  +- Ransomware               ¦
¦  +- Beacon                   ¦
¦  +- DGA                      ¦
¦  +- DNS                      ¦
¦  +- LOLBin                   ¦
¦  +- UEBA                     ¦
¦  +- Firewall                 ¦
¦  +- Network                  ¦
¦  +- Exploit                  ¦
¦  +- ASR                      ¦
¦  +- Memory                   ¦
+------------------------------+
    ?
Detections ? ThreatInfo ? UI + AuditLog + StateStore
`

## Security Modules Architecture

### Module Trait (crates/core/src/module.rs)
`ust
#[async_trait]
pub trait SecurityModule: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    async fn initialize(&mut self) -> Result<()>;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    fn health(&self) -> ModuleHealth;
    async fn handle_event(&self, event: &SecurityEventEnvelope) -> Result<()>;
    fn config_schema(&self) -> serde_json::Value;
}
`

### Module Categories

#### Detection Modules
- Process event analysis (EDR, Behavior, LOLBin)
- Memory analysis (Injection, Fileless, Memory integrity, Exploit)
- Network analysis (Beacon, DGA, DNS, Network)
- User analysis (UEBA)
- File analysis (AV, Ransomware)
- Compliance (Hardening, ASR)

#### Response Modules
- Firewall (block connections)
- Action Executor (quarantine, kill process)
- Forensic (evidence collection)

## MITRE ATT&CK Coverage

| Tactic | Technique | Module |
|--------|-----------|--------|
| Initial Access | T1566 Phishing | Fileless, ASR |
| Execution | T1059 Command Scripting | Fileless, LOLBin |
| Execution | T1055 Process Injection | Injection, EDR |
| Persistence | T1547 Registry Run Keys | Persistence |
| Privilege Escalation | T1068 Exploitation | Exploit |
| Defense Evasion | T1218 Signed Binary | LOLBin, ASR |
| Credential Access | T1003 OS Credentials | Credential |
| Discovery | T1046 Network Scan | Network |
| Lateral Movement | T1021 Remote Services | Network, Beacon |
| Collection | T1005 Data from Local | Ransomware, DLP |
| C2 | T1071 Application Layer | Beacon, DNS |
| Exfiltration | T1041 Exfil Over C2 | Network, UEBA |

## Crypto Architecture
- **At rest**: AES-256-GCM for stored data
- **In transit**: TLS 1.3 (for any external communication)
- **Audit**: SHA-256 hash chain for tamper evidence
- **Keys**: Derived from master key via HKDF
- **TPM**: Sealed keys for hardware-bound security (future)

## Performance Architecture
- **Async everywhere**: Tokio runtime, no blocking in event path
- **Zero-copy**: redb provides zero-copy reads
- **Bounded channels**: EventBus at 100k prevents unbounded memory growth
- **Lazy initialization**: Modules initialize on demand
- **Batch processing**: Events batched for throughput

## Threat Model
- **Local only**: No network listening, all communication via IPC
- **SYSTEM service**: Maximum privilege for kernel access
- **PPL protection**: Protected Process Light prevents tampering
- **Hash chain audit**: Any modification detectable
- **No external calls**: All detection is local, no cloud dependency
