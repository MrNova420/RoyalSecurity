pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InjectionType {
    DllInjection,
    ProcessHollowing,
    ApcInjection,
    ThreadHijack,
    ModuleStomping,
    ReflectiveDllLoading,
    ProcessDoppelnging,
    AtomBombing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionDetection {
    pub id: Uuid,
    pub injection_type: InjectionType,
    pub source_pid: u32,
    pub target_pid: u32,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionIndicator {
    pub indicator_type: String,
    pub value: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: u64,
    pub protection: MemoryProtection,
    pub allocation_type: String,
    pub timestamp: DateTime<Utc>,
    pub is_module_backed: bool,
    pub module_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteThread {
    pub source_pid: u32,
    pub target_pid: u32,
    pub thread_id: u32,
    pub start_address: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    pub detect_dll_injection: bool,
    pub detect_process_hollowing: bool,
    pub detect_apc_injection: bool,
    pub detect_thread_hijack: bool,
    pub detect_module_stomping: bool,
    pub detect_reflective_loading: bool,
    pub suspicious_rwx_threshold: u32,
    pub protected_processes: Vec<String>,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            detect_dll_injection: true,
            detect_process_hollowing: true,
            detect_apc_injection: true,
            detect_thread_hijack: true,
            detect_module_stomping: true,
            detect_reflective_loading: true,
            suspicious_rwx_threshold: 3,
            protected_processes: vec![
                "lsass.exe".into(),
                "csrss.exe".into(),
                "winlogon.exe".into(),
                "services.exe".into(),
            ],
        }
    }
}

fn is_legitimate_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    let legitimate = [
        "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe",
        "iexplore.exe", "java.exe", "javaw.exe", "jusched.exe",
        "code.exe", "devenv.exe", "msbuild.exe", "dotnet.exe",
        "node.exe", "python.exe", "python3.exe", "ruby.exe",
        "devenv.exe", "rider64.exe", "clion64.exe", "webstorm64.exe",
    ];
    legitimate.iter().any(|p| lower == *p)
}

fn is_protected_process(name: &str, config: &InjectionConfig) -> bool {
    let lower = name.to_lowercase();
    config.protected_processes.iter().any(|p| lower == p.to_lowercase())
}

fn integrity_level_rank(level: &str) -> u32 {
    match level.to_lowercase().as_str() {
        "untrusted" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "system" => 4,
        _ => 2,
    }
}

pub struct InjectionDetector {
    pub process_memory_map: HashMap<u32, Vec<MemoryRegion>>,
    pub remote_threads: Vec<RemoteThread>,
    pub detections: Vec<InjectionDetection>,
    pub config: InjectionConfig,
    pub detection_count: u64,
    suspended_threads: HashMap<u32, Vec<u32>>,
    rwx_allocation_counts: HashMap<u32, u32>,
    process_creation_times: HashMap<u32, DateTime<Utc>>,
    recently_hollowed: HashMap<u32, DateTime<Utc>>,
}

impl InjectionDetector {
    pub fn new() -> Self {
        Self {
            process_memory_map: HashMap::new(),
            remote_threads: Vec::new(),
            detections: Vec::new(),
            config: InjectionConfig::default(),
            detection_count: 0,
            suspended_threads: HashMap::new(),
            rwx_allocation_counts: HashMap::new(),
            process_creation_times: HashMap::new(),
            recently_hollowed: HashMap::new(),
        }
    }

    pub fn with_config(config: InjectionConfig) -> Self {
        Self {
            process_memory_map: HashMap::new(),
            remote_threads: Vec::new(),
            detections: Vec::new(),
            config,
            detection_count: 0,
            suspended_threads: HashMap::new(),
            rwx_allocation_counts: HashMap::new(),
            process_creation_times: HashMap::new(),
            recently_hollowed: HashMap::new(),
        }
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn clear_detections(&mut self) {
        self.detections.clear();
        self.detection_count = 0;
    }

    pub fn analyze_memory_event(&mut self, event: &MemoryEvent) -> Vec<InjectionDetection> {
        let mut detections = Vec::new();

        let region = MemoryRegion {
            base_address: event.base_address,
            size: event.region_size,
            protection: event.protection,
            allocation_type: event.allocation_type.clone(),
            timestamp: event.timestamp,
            is_module_backed: false,
            module_path: None,
        };

        self.process_memory_map
            .entry(event.process_id)
            .or_default()
            .push(region);

        if event.protection == MemoryProtection::ReadWriteExecute {
            let count = self.rwx_allocation_counts
                .entry(event.process_id)
                .or_insert(0);
            *count += 1;

            if *count >= self.config.suspicious_rwx_threshold {
                let detection = InjectionDetection {
                    id: Uuid::new_v4(),
                    injection_type: InjectionType::ReflectiveDllLoading,
                    source_pid: 0,
                    target_pid: event.process_id,
                    severity: EventSeverity::High,
                    confidence: 0.7,
                    description: format!(
                        "Process {} allocated {} RWX regions exceeding threshold of {}",
                        event.process_id, *count, self.config.suspicious_rwx_threshold
                    ),
                    evidence: vec![
                        format!("Base address: 0x{:X}", event.base_address),
                        format!("Region size: {} bytes", event.region_size),
                        format!("Allocation type: {}", event.allocation_type),
                        format!("Total RWX allocations: {}", count),
                    ],
                    timestamp: Utc::now(),
                };
                warn!(
                    pid = event.process_id,
                    rwx_count = *count,
                    "Excessive RWX memory allocations detected"
                );
                detections.push(detection);
                self.detection_count += 1;
            }
        }

        if event.protection == MemoryProtection::ExecuteWriteCopy {
            let detection = InjectionDetection {
                id: Uuid::new_v4(),
                injection_type: InjectionType::ProcessHollowing,
                source_pid: 0,
                target_pid: event.process_id,
                severity: EventSeverity::Critical,
                confidence: 0.85,
                description: format!(
                    "ExecuteWriteCopy protection on PID {} indicates possible process hollowing",
                    event.process_id
                ),
                evidence: vec![
                    format!("Base address: 0x{:X}", event.base_address),
                    format!("Region size: {} bytes", event.region_size),
                    format!(
                        "ExecuteWriteCopy is typically only set during process hollowing or self-modifying code"
                    ),
                ],
                timestamp: Utc::now(),
            };
            warn!(
                pid = event.process_id,
                addr = event.base_address,
                "ExecuteWriteCopy memory protection detected - possible process hollowing"
            );
            detections.push(detection);
            self.detection_count += 1;
        }

        if let Some(regions) = self.process_memory_map.get(&event.process_id) {
            let rw_count = regions.iter().filter(|r| matches!(r.protection,
                MemoryProtection::ReadWrite | MemoryProtection::ReadWriteExecute
            )).count();

            let rx_count = regions.iter().filter(|r| matches!(r.protection,
                MemoryProtection::ReadExecute
            )).count();

            if rw_count > 2 && rx_count > 0 {
                let detection = InjectionDetection {
                    id: Uuid::new_v4(),
                    injection_type: InjectionType::ModuleStomping,
                    source_pid: 0,
                    target_pid: event.process_id,
                    severity: EventSeverity::Medium,
                    confidence: 0.5,
                    description: format!(
                        "PID {} has mixed RW and RX regions suggesting possible module stomping",
                        event.process_id
                    ),
                    evidence: vec![
                        format!("RW regions: {}", rw_count),
                        format!("RX regions: {}", rx_count),
                        format!("Total regions: {}", regions.len()),
                    ],
                    timestamp: Utc::now(),
                };
                debug!(
                    pid = event.process_id,
                    "Mixed RW/RX memory regions detected - possible module stomping"
                );
                detections.push(detection);
                self.detection_count += 1;
            }
        }

        detections
    }

    pub fn analyze_thread_event(
        &mut self,
        event: &ThreadEvent,
        processes: &HashMap<u32, ProcessInfo>,
    ) -> Vec<InjectionDetection> {
        let mut detections = Vec::new();

        match event.action {
            ThreadAction::RemoteCreated => {
                let target_name = processes
                    .get(&event.process_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_default();

                let severity = if is_protected_process(&target_name, &self.config) {
                    EventSeverity::Critical
                } else {
                    EventSeverity::High
                };

                let confidence = if is_protected_process(&target_name, &self.config) {
                    0.95
                } else if is_legitimate_process(&target_name) {
                    0.4
                } else {
                    0.75
                };

                let injection_type = if event.start_address < 0x10000 {
                    InjectionType::ApcInjection
                } else {
                    InjectionType::DllInjection
                };

                let remote = RemoteThread {
                    source_pid: 0,
                    target_pid: event.process_id,
                    thread_id: event.thread_id,
                    start_address: event.start_address,
                    timestamp: event.timestamp,
                };
                self.remote_threads.push(remote);

                let detection = InjectionDetection {
                    id: Uuid::new_v4(),
                    injection_type,
                    source_pid: 0,
                    target_pid: event.process_id,
                    severity,
                    confidence,
                    description: format!(
                        "Remote thread created in PID {} ({}) - {} injection indicator",
                        event.process_id, target_name,
                        if event.start_address < 0x10000 { "APC" } else { "DLL" }
                    ),
                    evidence: vec![
                        format!("Thread ID: {}", event.thread_id),
                        format!("Start address: 0x{:X}", event.start_address),
                        format!("Target process: {} (PID {})", target_name, event.process_id),
                        format!(
                            "Protected process: {}",
                            is_protected_process(&target_name, &self.config)
                        ),
                    ],
                    timestamp: Utc::now(),
                };

                warn!(
                    target_pid = event.process_id,
                    target = target_name,
                    thread_id = event.thread_id,
                    start_addr = event.start_address,
                    "Remote thread creation detected"
                );
                detections.push(detection);
                self.detection_count += 1;

                if is_protected_process(&target_name, &self.config) {
                    let critical = InjectionDetection {
                        id: Uuid::new_v4(),
                        injection_type: InjectionType::DllInjection,
                        source_pid: 0,
                        target_pid: event.process_id,
                        severity: EventSeverity::Critical,
                        confidence: 0.95,
                        description: format!(
                            "Remote thread created in protected process {} ({})",
                            target_name, event.process_id
                        ),
                        evidence: vec![
                            format!(
                                "Protected process list: {}",
                                self.config.protected_processes.join(", ")
                            ),
                            format!("Thread start address: 0x{:X}", event.start_address),
                        ],
                        timestamp: Utc::now(),
                    };
                    warn!(
                        pid = event.process_id,
                        target = target_name,
                        "CRITICAL: Injection into protected system process"
                    );
                    detections.push(critical);
                    self.detection_count += 1;
                }
            }

            ThreadAction::Suspended => {
                self.suspended_threads
                    .entry(event.process_id)
                    .or_default()
                    .push(event.thread_id);
            }

            ThreadAction::Resumed => {
                if let Some(suspended) = self.suspended_threads.get_mut(&event.process_id) {
                    if let Some(pos) = suspended.iter().position(|&t| t == event.thread_id) {
                        suspended.remove(pos);

                        let had_memory_change = self.process_memory_map
                            .get(&event.process_id)
                            .map(|regions| {
                                regions.iter().any(|r| {
                                    r.timestamp > event.timestamp
                                        && matches!(r.protection,
                                            MemoryProtection::ReadWriteExecute
                                            | MemoryProtection::ExecuteWriteCopy
                                        )
                                })
                            })
                            .unwrap_or(false);

                        if had_memory_change && self.config.detect_thread_hijack {
                            let detection = InjectionDetection {
                                id: Uuid::new_v4(),
                                injection_type: InjectionType::ThreadHijack,
                                source_pid: 0,
                                target_pid: event.process_id,
                                severity: EventSeverity::Critical,
                                confidence: 0.8,
                                description: format!(
                                    "Thread {} in PID {} was suspended, memory changed, then resumed - thread hijacking pattern",
                                    event.thread_id, event.process_id
                                ),
                                evidence: vec![
                                    format!("Thread ID: {}", event.thread_id),
                                    format!("Process ID: {}", event.process_id),
                                    format!("Memory protection change detected during suspension"),
                                    format!("Start address: 0x{:X}", event.start_address),
                                ],
                                timestamp: Utc::now(),
                            };
                            warn!(
                                pid = event.process_id,
                                tid = event.thread_id,
                                "Thread hijacking pattern detected"
                            );
                            detections.push(detection);
                            self.detection_count += 1;
                        }
                    }
                }
            }

            _ => {}
        }

        detections
    }

    pub fn analyze_process_event(
        &mut self,
        info: &ProcessInfo,
        parent_info: Option<&ProcessInfo>,
    ) -> Vec<InjectionDetection> {
        let mut detections = Vec::new();
        let now = Utc::now();

        self.process_creation_times.insert(info.pid, now);
        self.recently_hollowed.insert(info.pid, now);

        let is_suspicious_name = {
            let lower = info.name.to_lowercase();
            let suspicious = [
                "svchost.exe", "csrss.exe", "smss.exe", "lsass.exe",
                "services.exe", "winlogon.exe", "conhost.exe",
            ];
            let in_system_path = info.path.to_lowercase().contains("\\windows\\system32");
            suspicious.iter().any(|s| lower == *s) && !in_system_path
        };

        if is_suspicious_name && self.config.detect_process_hollowing {
            let detection = InjectionDetection {
                id: Uuid::new_v4(),
                injection_type: InjectionType::ProcessHollowing,
                source_pid: info.ppid,
                target_pid: info.pid,
                severity: EventSeverity::Critical,
                confidence: 0.9,
                description: format!(
                    "Suspicious process {} running from non-system path: {}",
                    info.name, info.path
                ),
                evidence: vec![
                    format!("Process name: {}", info.name),
                    format!("Process path: {}", info.path),
                    format!("Parent PID: {}", info.ppid),
                    format!(
                        "Expected system path should contain \\Windows\\System32"
                    ),
                ],
                timestamp: now,
            };
            warn!(
                pid = info.pid,
                name = info.name,
                path = info.path,
                "Process with system name running from non-system path - possible hollowing"
            );
            detections.push(detection);
            self.detection_count += 1;
        }

        if let Some(parent) = parent_info {
            if let (Some(child_il), Some(parent_il)) =
                (&info.integrity_level, &parent.integrity_level)
            {
                let child_rank = integrity_level_rank(child_il);
                let parent_rank = integrity_level_rank(parent_il);

                if child_rank > parent_rank {
                    let detection = InjectionDetection {
                        id: Uuid::new_v4(),
                        injection_type: InjectionType::DllInjection,
                        source_pid: parent.pid,
                        target_pid: info.pid,
                        severity: EventSeverity::High,
                        confidence: 0.7,
                        description: format!(
                            "Integrity level escalation: {} ({}) spawned {} ({}) with higher integrity",
                            parent.name, parent_il, info.name, child_il
                        ),
                        evidence: vec![
                            format!("Parent: {} (PID {}, integrity: {})", parent.name, parent.pid, parent_il),
                            format!("Child: {} (PID {}, integrity: {})", info.name, info.pid, child_il),
                            format!(
                                "Parent rank: {}, Child rank: {}",
                                parent_rank, child_rank
                            ),
                        ],
                        timestamp: now,
                    };
                    warn!(
                        parent = parent.name,
                        parent_il = parent_il,
                        child = info.name,
                        child_il = child_il,
                        "Integrity level mismatch between parent and child"
                    );
                    detections.push(detection);
                    self.detection_count += 1;
                }
            }
        }

        if self.config.detect_process_hollowing {
            let time_since_creation = now
                .signed_duration_since(now);
            let _ = time_since_creation;

            if let Some(parent) = parent_info {
                let parent_lower = parent.name.to_lowercase();
                let child_lower = info.name.to_lowercase();
                let suspicious_pairs = [
                    ("powershell.exe", "cmd.exe"),
                    ("wscript.exe", "mshta.exe"),
                    ("explorer.exe", "rundll32.exe"),
                    ("explorer.exe", "regsvr32.exe"),
                    ("explorer.exe", "msbuild.exe"),
                ];

                for (expected_parent, suspicious_child) in &suspicious_pairs {
                    if parent_lower == *expected_parent && child_lower == *suspicious_child {
                        let detection = InjectionDetection {
                            id: Uuid::new_v4(),
                            injection_type: InjectionType::ProcessHollowing,
                            source_pid: parent.pid,
                            target_pid: info.pid,
                            severity: EventSeverity::Medium,
                            confidence: 0.6,
                            description: format!(
                                "Suspicious parent-child pair: {} spawned {}",
                                parent.name, info.name
                            ),
                            evidence: vec![
                                format!("Parent: {} (PID {})", parent.name, parent.pid),
                                format!("Child: {} (PID {})", info.name, info.pid),
                                format!(
                                    "This parent-child combination is commonly used in injection chains"
                                ),
                            ],
                            timestamp: now,
                        };
                        debug!(
                            parent = parent.name,
                            child = info.name,
                            "Suspicious parent-child process pair detected"
                        );
                        detections.push(detection);
                        self.detection_count += 1;
                    }
                }
            }
        }

        if let Some(parent) = parent_info {
            let command_suspicious = info.command_line.to_lowercase().contains("-enc")
                || info.command_line.to_lowercase().contains("frombase64")
                || info.command_line.to_lowercase().contains("invoke-expression")
                || info.command_line.to_lowercase().contains("iex");

            if command_suspicious && self.config.detect_dll_injection {
                let detection = InjectionDetection {
                    id: Uuid::new_v4(),
                    injection_type: InjectionType::DllInjection,
                    source_pid: parent.pid,
                    target_pid: info.pid,
                    severity: EventSeverity::High,
                    confidence: 0.75,
                    description: format!(
                        "Process {} has suspicious encoded command line - possible shellcode injection",
                        info.name
                    ),
                    evidence: vec![
                        format!("Process: {} (PID {})", info.name, info.pid),
                        format!(
                            "Command line contains encoded/obfuscated content"
                        ),
                        format!("Parent: {} (PID {})", parent.name, parent.pid),
                    ],
                    timestamp: now,
                };
                warn!(
                    pid = info.pid,
                    name = info.name,
                    "Encoded command line detected - possible shellcode injection"
                );
                detections.push(detection);
                self.detection_count += 1;
            }
        }

        detections
    }

    pub fn check_reflective_loading(
        &mut self,
        process_id: u32,
        module_name: &str,
        base_address: u64,
    ) -> Option<InjectionDetection> {
        if !self.config.detect_reflective_loading {
            return None;
        }

        let reflective_signatures = [
            "ReflectiveLoader", "rfdll", "rdll", "Reflective",
            "RunReflection", "Loader", "invoke.Reflection",
        ];

        let is_reflective = reflective_signatures
            .iter()
            .any(|sig| module_name.to_lowercase().contains(&sig.to_lowercase()));

        let is_from_memory = base_address > 0x70000000
            && !module_name.contains('\\')
            && !module_name.contains('/');

        let suspicious_modules = [
            "dumpsvc.dll", "meterpreter.dll", "metsrv.dll",
            "reflective.dll", "shellexe.dll", "reverse.dll",
        ];

        let is_known_malicious = suspicious_modules
            .iter()
            .any(|m| module_name.to_lowercase() == m.to_lowercase());

        if is_reflective || (is_from_memory && is_known_malicious) {
            let detection = InjectionDetection {
                id: Uuid::new_v4(),
                injection_type: InjectionType::ReflectiveDllLoading,
                source_pid: 0,
                target_pid: process_id,
                severity: EventSeverity::Critical,
                confidence: if is_known_malicious { 0.95 } else { 0.8 },
                description: format!(
                    "Reflective DLL loading detected in PID {}: module '{}' at 0x{:X}",
                    process_id, module_name, base_address
                ),
                evidence: vec![
                    format!("Module name: {}", module_name),
                    format!("Base address: 0x{:X}", base_address),
                    format!(
                        "Reflective signature match: {}",
                        is_reflective
                    ),
                    format!("Memory-resident: {}", is_from_memory),
                    format!("Known malicious module: {}", is_known_malicious),
                    format!(
                        "MDSec pattern: module loaded without file backing"
                    ),
                ],
                timestamp: Utc::now(),
            };
            warn!(
                pid = process_id,
                module = module_name,
                addr = base_address,
                "Reflective DLL loading detected"
            );
            self.detection_count += 1;
            return Some(detection);
        }

        if is_from_memory && self.config.detect_reflective_loading {
            let regions = self.process_memory_map.get(&process_id);
            let in_rwx = regions
                .map(|rs| {
                    rs.iter().any(|r| {
                        base_address >= r.base_address
                            && base_address < r.base_address + r.size
                            && matches!(r.protection, MemoryProtection::ReadWriteExecute)
                    })
                })
                .unwrap_or(false);

            if in_rwx {
                let detection = InjectionDetection {
                    id: Uuid::new_v4(),
                    injection_type: InjectionType::ReflectiveDllLoading,
                    source_pid: 0,
                    target_pid: process_id,
                    severity: EventSeverity::High,
                    confidence: 0.7,
                    description: format!(
                        "Module '{}' at 0x{:X} in PID {} loaded in RWX memory - likely reflective",
                        module_name, base_address, process_id
                    ),
                    evidence: vec![
                        format!("Module: {}", module_name),
                        format!("Address: 0x{:X}", base_address),
                        format!("No file path backing detected"),
                        format!("Residing in RWX memory region"),
                    ],
                    timestamp: Utc::now(),
                };
                debug!(
                    pid = process_id,
                    module = module_name,
                    "Module loaded in RWX memory - possible reflective loading"
                );
                self.detection_count += 1;
                return Some(detection);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process_info(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 100,
            name: name.to_string(),
            path: format!("C:\\Windows\\System32\\{}", name),
            command_line: String::new(),
            user: "SYSTEM".to_string(),
            hash_sha256: None,
            integrity_level: Some("System".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_new_detector() {
        let detector = InjectionDetector::new();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.detections.is_empty());
        assert!(detector.process_memory_map.is_empty());
        assert!(detector.remote_threads.is_empty());
        assert!(detector.config.detect_dll_injection);
        assert!(detector.config.detect_process_hollowing);
        assert_eq!(detector.config.suspicious_rwx_threshold, 3);
    }

    #[test]
    fn test_analyze_memory_event_rwx_protected_process() {
        let mut detector = InjectionDetector::new();

        let mut processes = HashMap::new();
        let lsass = ProcessInfo {
            pid: 500,
            ppid: 100,
            name: "lsass.exe".to_string(),
            path: "C:\\Windows\\System32\\lsass.exe".to_string(),
            command_line: String::new(),
            user: "SYSTEM".to_string(),
            hash_sha256: None,
            integrity_level: Some("System".to_string()),
            timestamp: Utc::now(),
        };
        processes.insert(500, lsass);

        for _ in 0..4 {
            let event = MemoryEvent {
                process_id: 500,
                base_address: 0x7FFE0000,
                region_size: 0x10000,
                protection: MemoryProtection::ReadWriteExecute,
                allocation_type: "MEM_COMMIT".to_string(),
                timestamp: Utc::now(),
            };
            let dets = detector.analyze_memory_event(&event);
            if !dets.is_empty() {
                assert!(dets.iter().any(|d| d.severity == EventSeverity::High));
                assert!(dets.iter().any(|d| {
                    matches!(d.injection_type, InjectionType::ReflectiveDllLoading)
                }));
                return;
            }
        }
        panic!("Expected RWX threshold detection for protected process");
    }

    #[test]
    fn test_analyze_thread_event_remote_created() {
        let mut detector = InjectionDetector::new();

        let mut processes = HashMap::new();
        processes.insert(200, make_process_info(200, "target.exe"));

        let event = ThreadEvent {
            process_id: 200,
            thread_id: 4001,
            start_address: 0x0000000180001000,
            action: ThreadAction::RemoteCreated,
            timestamp: Utc::now(),
        };

        let dets = detector.analyze_thread_event(&event, &processes);
        assert!(!dets.is_empty());
        assert!(dets.iter().any(|d| d.target_pid == 200));
        assert!(dets.iter().any(|d| {
            matches!(
                d.injection_type,
                InjectionType::DllInjection | InjectionType::ApcInjection
            )
        }));
        assert_eq!(detector.remote_threads.len(), 1);
        assert_eq!(detector.remote_threads[0].target_pid, 200);
    }

    #[test]
    fn test_analyze_thread_event_protected_process_critical() {
        let mut detector = InjectionDetector::new();

        let mut processes = HashMap::new();
        let mut lsass = make_process_info(500, "lsass.exe");
        lsass.integrity_level = Some("System".to_string());
        processes.insert(500, lsass);

        let event = ThreadEvent {
            process_id: 500,
            thread_id: 4002,
            start_address: 0x0000000180001000,
            action: ThreadAction::RemoteCreated,
            timestamp: Utc::now(),
        };

        let dets = detector.analyze_thread_event(&event, &processes);
        let critical: Vec<_> = dets.iter().filter(|d| d.severity == EventSeverity::Critical).collect();
        assert!(!critical.is_empty(), "Expected critical severity for protected process injection");
    }

    #[test]
    fn test_analyze_process_event_integrity_mismatch() {
        let mut detector = InjectionDetector::new();

        let parent = ProcessInfo {
            pid: 100,
            ppid: 0,
            name: "low.exe".to_string(),
            path: "C:\\temp\\low.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Low".to_string()),
            timestamp: Utc::now(),
        };

        let child = ProcessInfo {
            pid: 200,
            ppid: 100,
            name: "high.exe".to_string(),
            path: "C:\\temp\\high.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("High".to_string()),
            timestamp: Utc::now(),
        };

        let dets = detector.analyze_process_event(&child, Some(&parent));
        assert!(!dets.is_empty());
        assert!(dets.iter().any(|d| d.severity == EventSeverity::High));
        assert!(dets.iter().any(|d| {
            d.description.contains("Integrity level escalation")
        }));
    }

    #[test]
    fn test_detection_count_increments() {
        let mut detector = InjectionDetector::new();
        assert_eq!(detector.detection_count(), 0);

        let mut processes = HashMap::new();
        processes.insert(100, make_process_info(100, "suspicious.exe"));

        let event = ThreadEvent {
            process_id: 100,
            thread_id: 5000,
            start_address: 0x1000,
            action: ThreadAction::RemoteCreated,
            timestamp: Utc::now(),
        };
        detector.analyze_thread_event(&event, &processes);
        assert_eq!(detector.detection_count(), 1);

        detector.clear_detections();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.detections.is_empty());
    }

    #[test]
    fn test_process_hollowing_suspicious_name() {
        let mut detector = InjectionDetector::new();

        let parent = ProcessInfo {
            pid: 1,
            ppid: 0,
            name: "explorer.exe".to_string(),
            path: "C:\\Windows\\explorer.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let child = ProcessInfo {
            pid: 999,
            ppid: 1,
            name: "svchost.exe".to_string(),
            path: "C:\\temp\\svchost.exe".to_string(),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: Some("Medium".to_string()),
            timestamp: Utc::now(),
        };

        let dets = detector.analyze_process_event(&child, Some(&parent));
        let hollowing: Vec<_> = dets.iter().filter(|d| {
            matches!(d.injection_type, InjectionType::ProcessHollowing)
        }).collect();
        assert!(!hollowing.is_empty(), "Expected process hollowing detection for svchost outside system32");
    }

    #[test]
    fn test_reflective_loading_detection() {
        let mut detector = InjectionDetector::new();

        let result = detector.check_reflective_loading(500, "ReflectiveLoader", 0x7FFE0000);
        assert!(result.is_some());
        let det = result.unwrap();
        assert!(matches!(det.injection_type, InjectionType::ReflectiveDllLoading));
        assert_eq!(det.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_reflective_loading_disabled() {
        let config = InjectionConfig {
            detect_reflective_loading: false,
            ..InjectionConfig::default()
        };
        let mut detector = InjectionDetector::with_config(config);
        let result = detector.check_reflective_loading(500, "ReflectiveLoader", 0x7FFE0000);
        assert!(result.is_none());
    }

    #[test]
    fn test_with_config() {
        let config = InjectionConfig {
            detect_dll_injection: false,
            suspicious_rwx_threshold: 10,
            protected_processes: vec!["lsass.exe".into()],
            ..InjectionConfig::default()
        };
        let detector = InjectionDetector::with_config(config.clone());
        assert!(!detector.config.detect_dll_injection);
        assert_eq!(detector.config.suspicious_rwx_threshold, 10);
        assert_eq!(detector.config.protected_processes.len(), 1);
    }

    #[test]
    fn test_execute_write_copy_detection() {
        let mut detector = InjectionDetector::new();

        let event = MemoryEvent {
            process_id: 300,
            base_address: 0x10000000,
            region_size: 0x50000,
            protection: MemoryProtection::ExecuteWriteCopy,
            allocation_type: "MEM_COMMIT".to_string(),
            timestamp: Utc::now(),
        };

        let dets = detector.analyze_memory_event(&event);
        assert!(!dets.is_empty());
        assert!(dets.iter().any(|d| d.severity == EventSeverity::Critical));
        assert!(dets.iter().any(|d| {
            matches!(d.injection_type, InjectionType::ProcessHollowing)
        }));
    }
}
