pub mod prelude;

use royalsecurity_common::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::{warn, info};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BehaviorConfig {
    pub max_process_history: usize,
    pub suspicious_parent_threshold: u32,
    pub rapid_file_ops_threshold: u32,
    pub network_burst_threshold: u64,
    pub privilege_escalation_alert: bool,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            max_process_history: 1000,
            suspicious_parent_threshold: 5,
            rapid_file_ops_threshold: 50,
            network_burst_threshold: 100,
            privilege_escalation_alert: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BehaviorEvent {
    pub event_type: String,
    pub target: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ProcessBehavior {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub events: Vec<BehaviorEvent>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub suspicious_score: u32,
}

#[derive(Debug, Clone)]
pub enum BehaviorPattern {
    Sequence(Vec<String>),
    Threshold { event_type: String, count: u32, window_secs: u64 },
    RareProcess { process_names: Vec<String> },
    SuspiciousParent { parent: String, children: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct BehaviorRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: BehaviorPattern,
    pub severity: EventSeverity,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct BehaviorAlert {
    pub id: Uuid,
    pub rule_id: String,
    pub process_pid: u32,
    pub process_name: String,
    pub description: String,
    pub severity: EventSeverity,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

pub struct BehaviorDetector {
    process_history: HashMap<u32, ProcessBehavior>,
    detection_rules: Vec<BehaviorRule>,
    alert_count: u64,
    config: BehaviorConfig,
    network_connections: Vec<(DateTime<Utc>, u32, String)>,
    file_ops_timestamps: Vec<(DateTime<Utc>, u32)>,
    registry_ops_timestamps: Vec<(DateTime<Utc>, String)>,
}

impl BehaviorDetector {
    pub fn new() -> Self {
        let config = BehaviorConfig::default();
        Self {
            process_history: HashMap::new(),
            detection_rules: Self::default_rules(),
            alert_count: 0,
            config,
            network_connections: Vec::new(),
            file_ops_timestamps: Vec::new(),
            registry_ops_timestamps: Vec::new(),
        }
    }

    pub fn with_config(config: BehaviorConfig) -> Self {
        Self {
            process_history: HashMap::new(),
            detection_rules: Self::default_rules(),
            alert_count: 0,
            config,
            network_connections: Vec::new(),
            file_ops_timestamps: Vec::new(),
            registry_ops_timestamps: Vec::new(),
        }
    }

    fn default_rules() -> Vec<BehaviorRule> {
        vec![
            BehaviorRule {
                id: "BH-001".into(),
                name: "Rare Process Spawning Shell".into(),
                description: "An uncommon parent process spawned a shell or scripting interpreter".into(),
                pattern: BehaviorPattern::RareProcess {
                    process_names: vec![
                        "cmd.exe".into(), "powershell.exe".into(), "bash".into(),
                        "sh".into(), "zsh".into(), "cscript.exe".into(), "wscript.exe".into(),
                    ],
                },
                severity: EventSeverity::High,
                enabled: true,
            },
            BehaviorRule {
                id: "BH-002".into(),
                name: "Mass File Operations".into(),
                description: "Process performing rapid file modifications indicative of encryption or wiping".into(),
                pattern: BehaviorPattern::Threshold {
                    event_type: "file_operation".into(),
                    count: 50,
                    window_secs: 60,
                },
                severity: EventSeverity::High,
                enabled: true,
            },
            BehaviorRule {
                id: "BH-003".into(),
                name: "Network Burst".into(),
                description: "Process made excessive network connections in short time window".into(),
                pattern: BehaviorPattern::Threshold {
                    event_type: "network_connection".into(),
                    count: 100,
                    window_secs: 60,
                },
                severity: EventSeverity::Medium,
                enabled: true,
            },
            BehaviorRule {
                id: "BH-004".into(),
                name: "RWX Memory Allocation".into(),
                description: "Process allocated memory with Read-Write-Execute permissions".into(),
                pattern: BehaviorPattern::RareProcess {
                    process_names: vec![],
                },
                severity: EventSeverity::High,
                enabled: true,
            },
            BehaviorRule {
                id: "BH-005".into(),
                name: "Remote Thread Creation".into(),
                description: "Remote thread created in another process".into(),
                pattern: BehaviorPattern::RareProcess {
                    process_names: vec![],
                },
                severity: EventSeverity::Critical,
                enabled: true,
            },
            BehaviorRule {
                id: "BH-006".into(),
                name: "Suspicious Parent-Child Chain".into(),
                description: "Suspicious parent process spawning known attack tools".into(),
                pattern: BehaviorPattern::SuspiciousParent {
                    parent: "explorer.exe".into(),
                    children: vec![
                        "cmd.exe".into(), "powershell.exe".into(), "mshta.exe".into(),
                        "regsvr32.exe".into(), "rundll32.exe".into(), "certutil.exe".into(),
                    ],
                },
                severity: EventSeverity::Medium,
                enabled: true,
            },
        ]
    }

    pub fn analyze_process_event(&mut self, info: &ProcessInfo) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        if let Some(parent_behavior) = self.process_history.get_mut(&info.ppid) {
            parent_behavior.events.push(BehaviorEvent {
                event_type: "child_process_created".into(),
                target: info.name.clone(),
                severity: EventSeverity::Informational,
                timestamp: now,
            });
            parent_behavior.last_seen = now;
            parent_behavior.suspicious_score += 1;

            let parent_name = parent_behavior.name.clone();
            let suspicious_parents = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrobat.exe", "chrome.exe", "firefox.exe"];

            if suspicious_parents.iter().any(|sp| parent_name.to_lowercase() == *sp) {
                let shell_names = ["cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "cscript.exe", "wscript.exe"];
                if shell_names.iter().any(|s| info.name.to_lowercase() == *s) {
                    self.alert_count += 1;
                    let alert = BehaviorAlert {
                        id: Uuid::new_v4(),
                        rule_id: "BH-001".into(),
                        process_pid: info.pid,
                        process_name: info.name.clone(),
                        description: format!(
                            "Suspicious parent '{}' (PID {}) spawned shell '{}'. Possible document-based attack.",
                            parent_name, info.ppid, info.name
                        ),
                        severity: EventSeverity::High,
                        evidence: vec![
                            format!("Parent: {} (PID {})", parent_name, info.ppid),
                            format!("Child: {} (PID {})", info.name, info.pid),
                            format!("CommandLine: {}", info.command_line),
                            format!("User: {}", info.user),
                        ],
                        timestamp: now,
                    };
                    warn!(
                        rule_id = "BH-001",
                        parent = %parent_name,
                        child = %info.name,
                        pid = info.pid,
                        "Suspicious parent-child process chain detected"
                    );
                    alerts.push(alert);
                }
            }

            for rule in &self.detection_rules {
                if !rule.enabled {
                    continue;
                }
                if let BehaviorPattern::SuspiciousParent { parent, children } = &rule.pattern {
                    if parent_name.to_lowercase() == parent.to_lowercase() {
                        if children.iter().any(|c| info.name.to_lowercase() == c.to_lowercase()) {
                            self.alert_count += 1;
                            let alert = BehaviorAlert {
                                id: Uuid::new_v4(),
                                rule_id: rule.id.clone(),
                                process_pid: info.pid,
                                process_name: info.name.clone(),
                                description: format!(
                                    "Rule '{}': Parent '{}' spawned suspicious child '{}'",
                                    rule.name, parent_name, info.name
                                ),
                                severity: rule.severity.clone(),
                                evidence: vec![
                                    format!("Rule: {} ({})", rule.name, rule.id),
                                    format!("Parent: {} (PID {})", parent_name, info.ppid),
                                    format!("Child: {} (PID {})", info.name, info.pid),
                                ],
                                timestamp: now,
                            };
                            alerts.push(alert);
                        }
                    }
                }
            }
        }

        let behavior = ProcessBehavior {
            pid: info.pid,
            ppid: info.ppid,
            name: info.name.clone(),
            events: vec![BehaviorEvent {
                event_type: "process_created".into(),
                target: info.path.clone(),
                severity: EventSeverity::Informational,
                timestamp: now,
            }],
            first_seen: now,
            last_seen: now,
            suspicious_score: 0,
        };

        if self.process_history.len() >= self.config.max_process_history {
            if let Some(oldest_pid) = self.process_history.keys().min().copied() {
                self.process_history.remove(&oldest_pid);
            }
        }
        self.process_history.insert(info.pid, behavior);

        info!(
            pid = info.pid,
            ppid = info.ppid,
            name = %info.name,
            "Process event tracked"
        );

        alerts
    }

    pub fn analyze_file_event(&mut self, event: &FileEvent, pid: Option<u32>) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();
        let process_id = pid.unwrap_or(0);

        self.file_ops_timestamps.push((now, process_id));

        self.file_ops_timestamps.retain(|(ts, _)| {
            now.signed_duration_since(*ts).num_seconds() < 120
        });

        let recent_ops: Vec<_> = self.file_ops_timestamps.iter()
            .filter(|(ts, pid)| *pid == process_id && now.signed_duration_since(*ts).num_seconds() < 60)
            .collect();

        if (recent_ops.len() as u32) >= self.config.rapid_file_ops_threshold {
            let ext: String = event.path.rsplit('.').next().unwrap_or("").into();
            let suspicious_exts = ["docx", "xlsx", "pdf", "jpg", "png", "txt", "csv", "db", "sql", "bak"];
            let is_targeted = suspicious_exts.contains(&ext.as_str());

            if is_targeted || matches!(event.action, FileAction::Modified | FileAction::Renamed) {
                self.alert_count += 1;
                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    rule_id: "BH-002".into(),
                    process_pid: process_id,
                    process_name: self.process_history.get(&process_id)
                        .map(|b| b.name.clone())
                        .unwrap_or_else(|| "unknown".into()),
                    description: format!(
                        "Mass file operations detected: {} operations in 60s by PID {}. Possible ransomware or wiping activity.",
                        recent_ops.len(), process_id
                    ),
                    severity: EventSeverity::High,
                    evidence: vec![
                        format!("Process PID: {}", process_id),
                        format!("Operations in last 60s: {}", recent_ops.len()),
                        format!("Sample target: {}", event.path),
                        format!("Action: {:?}", event.action),
                    ],
                    timestamp: now,
                };
                warn!(
                    rule_id = "BH-002",
                    pid = process_id,
                    ops_count = recent_ops.len(),
                    "Mass file operations detected"
                );
                alerts.push(alert);
            }
        }

        let system_dirs = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "/usr/bin", "/usr/sbin", "/etc"];
        let in_system_dir = system_dirs.iter().any(|d| event.path.starts_with(d));

        if in_system_dir && matches!(event.action, FileAction::Created | FileAction::Modified) {
            if let Some(parent_behavior) = self.process_history.get_mut(&process_id) {
                parent_behavior.suspicious_score += 5;
                parent_behavior.events.push(BehaviorEvent {
                    event_type: "file_operation_system_dir".into(),
                    target: event.path.clone(),
                    severity: EventSeverity::High,
                    timestamp: now,
                });
                parent_behavior.last_seen = now;
            }

            self.alert_count += 1;
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                rule_id: "BH-002".into(),
                process_pid: process_id,
                process_name: self.process_history.get(&process_id)
                    .map(|b| b.name.clone())
                    .unwrap_or_else(|| "unknown".into()),
                description: format!(
                    "File {} in system directory: {} by PID {}. Suspicious modification of system file.",
                    if matches!(event.action, FileAction::Created) { "created" } else { "modified" },
                    event.path, process_id
                ),
                severity: EventSeverity::High,
                evidence: vec![
                    format!("Path: {}", event.path),
                    format!("Action: {:?}", event.action),
                    format!("Process PID: {}", process_id),
                ],
                timestamp: now,
            };
            alerts.push(alert);
        }

        if let Some(behavior) = self.process_history.get(&process_id) {
            let is_first_event = behavior.events.last()
                .map(|e| e.event_type == "process_created")
                .unwrap_or(false);
            if is_first_event && matches!(event.action, FileAction::Created | FileAction::Modified) {
                if let Some(b) = self.process_history.get_mut(&process_id) {
                    b.suspicious_score += 2;
                }
            }
        }

        alerts
    }

    pub fn analyze_network_event(&mut self, event: &NetworkEvent) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();
        let pid = event.process_pid.unwrap_or(0);

        self.network_connections.push((now, pid, event.process_name.clone().unwrap_or_default()));

        self.network_connections.retain(|(ts, _, _)| {
            now.signed_duration_since(*ts).num_seconds() < 120
        });

        let recent_connections: Vec<_> = self.network_connections.iter()
            .filter(|(ts, p, _)| *p == pid && now.signed_duration_since(*ts).num_seconds() < 60)
            .collect();

        if (recent_connections.len() as u64) >= self.config.network_burst_threshold {
            self.alert_count += 1;
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                rule_id: "BH-003".into(),
                process_pid: pid,
                process_name: event.process_name.clone().unwrap_or_else(|| "unknown".into()),
                description: format!(
                    "Network burst detected: {} connections in 60s by PID {}. Possible C2 beaconing or data exfiltration.",
                    recent_connections.len(), pid
                ),
                severity: EventSeverity::Medium,
                evidence: vec![
                    format!("Process: {} (PID {})", event.process_name.as_deref().unwrap_or("unknown"), pid),
                    format!("Connections in last 60s: {}", recent_connections.len()),
                    format!("Destination: {}:{}", event.dst_ip.map(|i| i.to_string()).unwrap_or_default(), event.dst_port),
                    format!("Bytes in/out: {}/{}", event.bytes_in, event.bytes_out),
                ],
                timestamp: now,
            };
            warn!(
                rule_id = "BH-003",
                pid = pid,
                connections = recent_connections.len(),
                "Network burst detected"
            );
            alerts.push(alert);
        }

        let common_ports = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 445, 139, 8080, 8443];
        let rare_port = !common_ports.contains(&event.dst_port) && event.dst_port != 0;

        if rare_port && event.dst_port > 0 {
            if let Some(ref mut behavior) = self.process_history.get_mut(&pid) {
                behavior.suspicious_score += 3;
                behavior.events.push(BehaviorEvent {
                    event_type: "network_connection_rare_port".into(),
                    target: format!("{}:{}", event.dst_ip.map(|i| i.to_string()).unwrap_or_default(), event.dst_port),
                    severity: EventSeverity::Medium,
                    timestamp: now,
                });
                behavior.last_seen = now;
            }
        }

        if let Some(ref dst_ip) = event.dst_ip {
            let ip_str = dst_ip.to_string();
            let private_ranges = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."];
            let is_private = private_ranges.iter().any(|r| ip_str.starts_with(r));

            if !is_private && event.dst_port != 0 && !common_ports.contains(&event.dst_port) {
                self.alert_count += 1;
                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    rule_id: "BH-003".into(),
                    process_pid: pid,
                    process_name: event.process_name.clone().unwrap_or_else(|| "unknown".into()),
                    description: format!(
                        "Connection to external rare port {} from PID {}. Possible covert channel.",
                        event.dst_port, pid
                    ),
                    severity: EventSeverity::Medium,
                    evidence: vec![
                        format!("Destination: {}:{}", ip_str, event.dst_port),
                        format!("Process: {} (PID {})", event.process_name.as_deref().unwrap_or("unknown"), pid),
                        format!("Protocol: {:?}", event.protocol),
                    ],
                    timestamp: now,
                };
                alerts.push(alert);
            }
        }

        alerts
    }

    pub fn analyze_registry_event(&mut self, event: &RegistryEvent, pid: Option<u32>) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();
        let process_id = pid.unwrap_or(0);

        self.registry_ops_timestamps.push((now, event.key_path.clone()));
        self.registry_ops_timestamps.retain(|(ts, _)| {
            now.signed_duration_since(*ts).num_seconds() < 120
        });

        let recent_ops: Vec<_> = self.registry_ops_timestamps.iter()
            .filter(|(ts, path)| path == &event.key_path && now.signed_duration_since(*ts).num_seconds() < 30)
            .collect();

        if recent_ops.len() >= 10 {
            self.alert_count += 1;
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                rule_id: "BH-002".into(),
                process_pid: process_id,
                process_name: self.process_history.get(&process_id)
                    .map(|b| b.name.clone())
                    .unwrap_or_else(|| "unknown".into()),
                description: format!(
                    "Rapid registry modifications: {} changes to '{}' in 30s. Possible persistence mechanism installation.",
                    recent_ops.len(), event.key_path
                ),
                severity: EventSeverity::High,
                evidence: vec![
                    format!("Key: {}", event.key_path),
                    format!("Value: {:?}", event.value_name),
                    format!("Action: {:?}", event.action),
                    format!("Modifications in 30s: {}", recent_ops.len()),
                    format!("Process PID: {}", process_id),
                ],
                timestamp: now,
            };
            warn!(
                rule_id = "BH-002",
                key = %event.key_path,
                modifications = recent_ops.len(),
                "Rapid registry modifications detected"
            );
            alerts.push(alert);
        }

        let persistence_keys = [
            "CurrentVersion\\Run",
            "CurrentVersion\\RunOnce",
            "CurrentVersion\\Windows",
            "Winlogon",
            "Services",
            "CurrentVersion\\Explorer\\Shell Folders",
            "CurrentVersion\\Explorer\\User Shell Folders",
        ];

        if persistence_keys.iter().any(|k| event.key_path.to_lowercase().contains(&k.to_lowercase())) {
            if matches!(event.action, RegistryAction::Created | RegistryAction::Modified) {
                self.alert_count += 1;
                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    rule_id: "BH-006".into(),
                    process_pid: process_id,
                    process_name: self.process_history.get(&process_id)
                        .map(|b| b.name.clone())
                        .unwrap_or_else(|| "unknown".into()),
                    description: format!(
                        "Persistence registry key modified: '{}' value_name='{:?}' by PID {}. Possible persistence mechanism.",
                        event.key_path, event.value_name, process_id
                    ),
                    severity: EventSeverity::High,
                    evidence: vec![
                        format!("Key: {}", event.key_path),
                        format!("Value: {:?}", event.value_name),
                        format!("Data: {:?}", event.value_data),
                        format!("Action: {:?}", event.action),
                        format!("Process PID: {}", process_id),
                    ],
                    timestamp: now,
                };
                alerts.push(alert);
            }
        }

        if let Some(ref mut behavior) = self.process_history.get_mut(&process_id) {
            behavior.suspicious_score += 1;
            behavior.events.push(BehaviorEvent {
                event_type: "registry_operation".into(),
                target: event.key_path.clone(),
                severity: EventSeverity::Informational,
                timestamp: now,
            });
            behavior.last_seen = now;
        }

        alerts
    }

    pub fn analyze_memory_event(&mut self, event: &MemoryEvent) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        let is_rwx = matches!(event.protection, MemoryProtection::ReadWriteExecute | MemoryProtection::ExecuteWriteCopy);

        if is_rwx {
            let standard_browsers = ["chrome.exe", "firefox.exe", "msedge.exe", "safari.exe"];
            let standard_system = ["csrss.exe", "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe", "smss.exe"];

            let process_name = self.process_history.get(&event.process_id)
                .map(|b| b.name.clone())
                .unwrap_or_else(|| "unknown".into());
            let name_lower = process_name.to_lowercase();

            let is_standard = standard_browsers.iter().any(|s| name_lower == *s)
                || standard_system.iter().any(|s| name_lower == *s);

            if !is_standard {
                self.alert_count += 1;

                if let Some(ref mut behavior) = self.process_history.get_mut(&event.process_id) {
                    behavior.suspicious_score += 10;
                    behavior.events.push(BehaviorEvent {
                        event_type: "rwx_memory_allocation".into(),
                        target: format!("0x{:x}", event.base_address),
                        severity: EventSeverity::High,
                        timestamp: now,
                    });
                    behavior.last_seen = now;
                }

                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    rule_id: "BH-004".into(),
                    process_pid: event.process_id,
                    process_name: self.process_history.get(&event.process_id)
                        .map(|b| b.name.clone())
                        .unwrap_or_else(|| "unknown".into()),
                    description: format!(
                        "RWX memory allocation at 0x{:x} (size: {} bytes) in PID {} ({:}). Potential shellcode injection.",
                        event.base_address, event.region_size, event.process_id, process_name
                    ),
                    severity: EventSeverity::High,
                    evidence: vec![
                        format!("Base Address: 0x{:x}", event.base_address),
                        format!("Region Size: {} bytes", event.region_size),
                        format!("Protection: {:?}", event.protection),
                        format!("Allocation Type: {}", event.allocation_type),
                        format!("Process: {} (PID {})", process_name, event.process_id),
                    ],
                    timestamp: now,
                };
                warn!(
                    rule_id = "BH-004",
                    pid = event.process_id,
                    address = format_args!("0x{:x}", event.base_address),
                    "RWX memory allocation detected"
                );
                alerts.push(alert);
            }
        }

        alerts
    }

    pub fn analyze_thread_event(&mut self, event: &ThreadEvent) -> Vec<BehaviorAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        if matches!(event.action, ThreadAction::RemoteCreated) {
            let process_name = self.process_history.get(&event.process_id)
                .map(|b| b.name.clone())
                .unwrap_or_else(|| "unknown".into());

            let target_system = ["csrss.exe", "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe", "smss.exe", "fontdrvhost.exe"];
            let name_lower = process_name.to_lowercase();
            let is_system_target = target_system.iter().any(|s| name_lower == *s);

            if is_system_target {
                self.alert_count += 1;

                if let Some(ref mut behavior) = self.process_history.get_mut(&event.process_id) {
                    behavior.suspicious_score += 15;
                    behavior.events.push(BehaviorEvent {
                        event_type: "remote_thread_system_process".into(),
                        target: format!("thread_id={}", event.thread_id),
                        severity: EventSeverity::Critical,
                        timestamp: now,
                    });
                    behavior.last_seen = now;
                }

                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    rule_id: "BH-005".into(),
                    process_pid: event.process_id,
                    process_name: process_name.clone(),
                    description: format!(
                        "Remote thread created in critical system process '{}' (PID {}, thread {}). Potential code injection or privilege escalation.",
                        process_name, event.process_id, event.thread_id
                    ),
                    severity: EventSeverity::Critical,
                    evidence: vec![
                        format!("Target Process: {} (PID {})", process_name, event.process_id),
                        format!("Thread ID: {}", event.thread_id),
                        format!("Start Address: 0x{:x}", event.start_address),
                        format!("Action: {:?}", event.action),
                    ],
                    timestamp: now,
                };
                warn!(
                    rule_id = "BH-005",
                    target_pid = event.process_id,
                    thread_id = event.thread_id,
                    "Remote thread creation in system process detected"
                );
                alerts.push(alert);
            } else {
                self.alert_count += 1;

                if let Some(ref mut behavior) = self.process_history.get_mut(&event.process_id) {
                    behavior.suspicious_score += 8;
                    behavior.events.push(BehaviorEvent {
                        event_type: "remote_thread".into(),
                        target: format!("thread_id={}", event.thread_id),
                        severity: EventSeverity::High,
                        timestamp: now,
                    });
                    behavior.last_seen = now;
                }

                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    rule_id: "BH-005".into(),
                    process_pid: event.process_id,
                    process_name: process_name.clone(),
                    description: format!(
                        "Remote thread created in process '{}' (PID {}, thread {}). Possible DLL injection.",
                        process_name, event.process_id, event.thread_id
                    ),
                    severity: EventSeverity::High,
                    evidence: vec![
                        format!("Target Process: {} (PID {})", process_name, event.process_id),
                        format!("Thread ID: {}", event.thread_id),
                        format!("Start Address: 0x{:x}", event.start_address),
                    ],
                    timestamp: now,
                };
                alerts.push(alert);
            }
        }

        alerts
    }

    pub fn get_suspicious_processes(&self) -> Vec<(u32, u32)> {
        let threshold = self.config.suspicious_parent_threshold;
        self.process_history.values()
            .filter(|b| b.suspicious_score >= threshold)
            .map(|b| (b.pid, b.suspicious_score))
            .collect()
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }

    pub fn reset(&mut self) {
        self.process_history.clear();
        self.alert_count = 0;
        self.network_connections.clear();
        self.file_ops_timestamps.clear();
        self.registry_ops_timestamps.clear();
        info!("Behavior detector reset");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process_info(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.into(),
            path: format!("C:\\Windows\\System32\\{}", name),
            command_line: String::new(),
            user: "user".into(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_behavior_detector_new() {
        let detector = BehaviorDetector::new();
        assert_eq!(detector.alert_count(), 0);
        assert!(detector.process_history.is_empty());
        assert!(!detector.detection_rules.is_empty());
        assert_eq!(detector.detection_rules.len(), 6);
    }

    #[test]
    fn test_analyze_process_event_creates_tracking_entries() {
        let mut detector = BehaviorDetector::new();
        let info = make_process_info(100, 1, "notepad.exe");

        let alerts = detector.analyze_process_event(&info);

        assert!(detector.process_history.contains_key(&100));
        let behavior = detector.process_history.get(&100).unwrap();
        assert_eq!(behavior.pid, 100);
        assert_eq!(behavior.ppid, 1);
        assert_eq!(behavior.name, "notepad.exe");
        assert_eq!(behavior.events.len(), 1);
        assert_eq!(behavior.events[0].event_type, "process_created");
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn test_analyze_process_event_detects_suspicious_parent_child() {
        let mut detector = BehaviorDetector::new();

        let parent = make_process_info(1, 0, "winword.exe");
        detector.analyze_process_event(&parent);

        let child = make_process_info(100, 1, "powershell.exe");
        let alerts = detector.analyze_process_event(&child);

        assert!(!alerts.is_empty(), "Should detect suspicious parent-child chain");
        assert_eq!(alerts[0].severity, EventSeverity::High);
        assert_eq!(alerts[0].rule_id, "BH-001");
        assert!(alerts[0].description.contains("winword.exe"));
    }

    #[test]
    fn test_analyze_file_event_detects_rapid_modifications() {
        let config = BehaviorConfig {
            rapid_file_ops_threshold: 5,
            ..Default::default()
        };
        let mut detector = BehaviorDetector::with_config(config);

        for i in 0..10 {
            let event = FileEvent {
                path: format!("C:\\Users\\test\\Documents\\file{}.docx", i),
                original_path: None,
                action: FileAction::Modified,
                hash_sha256: None,
                size: None,
                timestamp: Utc::now(),
            };
            let alerts = detector.analyze_file_event(&event, Some(200));
            if !alerts.is_empty() {
                assert_eq!(alerts[0].severity, EventSeverity::High);
                assert_eq!(alerts[0].rule_id, "BH-002");
                return;
            }
        }
        panic!("Should have detected rapid file modifications");
    }

    #[test]
    fn test_analyze_network_event_detects_burst_connections() {
        let config = BehaviorConfig {
            network_burst_threshold: 5,
            ..Default::default()
        };
        let mut detector = BehaviorDetector::with_config(config);

        for i in 0..10 {
            let event = NetworkEvent {
                src_ip: Some("192.168.1.1".parse().unwrap()),
                dst_ip: Some("10.0.0.1".parse().unwrap()),
                src_port: 50000 + i as u16,
                dst_port: 443,
                protocol: Protocol::Tcp,
                bytes_in: 1024,
                bytes_out: 512,
                process_name: Some("malware.exe".into()),
                process_pid: Some(300),
                timestamp: Utc::now(),
            };
            let alerts = detector.analyze_network_event(&event);
            if !alerts.is_empty() {
                assert_eq!(alerts[0].severity, EventSeverity::Medium);
                assert_eq!(alerts[0].rule_id, "BH-003");
                return;
            }
        }
        panic!("Should have detected network burst");
    }

    #[test]
    fn test_get_suspicious_processes_returns_scored_processes() {
        let config = BehaviorConfig {
            suspicious_parent_threshold: 2,
            ..Default::default()
        };
        let mut detector = BehaviorDetector::with_config(config);

        let parent = make_process_info(1, 0, "explorer.exe");
        detector.analyze_process_event(&parent);

        let shell1 = make_process_info(100, 1, "cmd.exe");
        detector.analyze_process_event(&shell1);

        let shell2 = make_process_info(101, 1, "powershell.exe");
        detector.analyze_process_event(&shell2);

        let shell3 = make_process_info(102, 1, "cmd.exe");
        detector.analyze_process_event(&shell3);

        let suspicious = detector.get_suspicious_processes();
        assert!(!suspicious.is_empty(), "Should have suspicious processes");
        for (_pid, score) in &suspicious {
            assert!(*score >= detector.config.suspicious_parent_threshold);
        }
    }

    #[test]
    fn test_analyze_memory_event_detects_rwx_allocations() {
        let mut detector = BehaviorDetector::new();

        let info = make_process_info(500, 1, "myapp.exe");
        detector.analyze_process_event(&info);

        let event = MemoryEvent {
            process_id: 500,
            base_address: 0x7FF00000,
            region_size: 4096,
            protection: MemoryProtection::ReadWriteExecute,
            allocation_type: "MEM_COMMIT".into(),
            timestamp: Utc::now(),
        };

        let alerts = detector.analyze_memory_event(&event);
        assert!(!alerts.is_empty(), "Should detect RWX allocation in non-standard process");
        assert_eq!(alerts[0].severity, EventSeverity::High);
        assert_eq!(alerts[0].rule_id, "BH-004");

        let behavior = detector.process_history.get(&500).unwrap();
        assert!(behavior.suspicious_score >= 10);
    }

    #[test]
    fn test_analyze_memory_event_ignores_standard_processes() {
        let mut detector = BehaviorDetector::new();

        let info = make_process_info(500, 1, "chrome.exe");
        detector.analyze_process_event(&info);

        let event = MemoryEvent {
            process_id: 500,
            base_address: 0x7FF00000,
            region_size: 4096,
            protection: MemoryProtection::ReadWriteExecute,
            allocation_type: "MEM_COMMIT".into(),
            timestamp: Utc::now(),
        };

        let alerts = detector.analyze_memory_event(&event);
        assert!(alerts.is_empty(), "Should not alert on standard process RWX");
    }

    #[test]
    fn test_analyze_thread_event_detects_remote_thread() {
        let mut detector = BehaviorDetector::new();

        let info = make_process_info(600, 1, "malware.exe");
        detector.analyze_process_event(&info);

        let event = ThreadEvent {
            process_id: 600,
            thread_id: 7000,
            start_address: 0x7FF80000,
            action: ThreadAction::RemoteCreated,
            timestamp: Utc::now(),
        };

        let alerts = detector.analyze_thread_event(&event);
        assert!(!alerts.is_empty(), "Should detect remote thread creation");
        assert_eq!(alerts[0].rule_id, "BH-005");
    }

    #[test]
    fn test_reset_clears_all_state() {
        let mut detector = BehaviorDetector::new();

        let info = make_process_info(100, 1, "notepad.exe");
        detector.analyze_process_event(&info);

        let event = NetworkEvent {
            src_ip: None,
            dst_ip: None,
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Tcp,
            bytes_in: 0,
            bytes_out: 0,
            process_name: None,
            process_pid: Some(100),
            timestamp: Utc::now(),
        };
        detector.analyze_network_event(&event);

        detector.reset();
        assert_eq!(detector.alert_count(), 0);
        assert!(detector.process_history.is_empty());
        assert!(detector.network_connections.is_empty());
        assert!(detector.file_ops_timestamps.is_empty());
        assert!(detector.registry_ops_timestamps.is_empty());
    }

    #[test]
    fn test_alert_count_increments() {
        let mut detector = BehaviorDetector::new();
        assert_eq!(detector.alert_count(), 0);

        let parent = make_process_info(1, 0, "winword.exe");
        detector.analyze_process_event(&parent);

        let child = make_process_info(100, 1, "powershell.exe");
        detector.analyze_process_event(&child);

        assert!(detector.alert_count() > 0);
    }

    #[test]
    fn test_with_config_custom_thresholds() {
        let config = BehaviorConfig {
            max_process_history: 10,
            suspicious_parent_threshold: 2,
            rapid_file_ops_threshold: 3,
            network_burst_threshold: 3,
            privilege_escalation_alert: false,
        };
        let detector = BehaviorDetector::with_config(config);

        assert_eq!(detector.config.max_process_history, 10);
        assert_eq!(detector.config.suspicious_parent_threshold, 2);
        assert_eq!(detector.config.rapid_file_ops_threshold, 3);
        assert_eq!(detector.config.network_burst_threshold, 3);
        assert!(!detector.config.privilege_escalation_alert);
    }
}
