pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
    pub sections: Vec<ModuleSection>,
    pub iat_entries: Vec<IatEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub data_hash: String,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry {
    pub function_name: String,
    pub dll_name: String,
    pub expected_address: u64,
    pub actual_address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub monitoring_interval_secs: u64,
    pub max_baseline_age_secs: u64,
    pub detect_inline_hooks: bool,
    pub detect_iat_hooks: bool,
    pub detect_detours: bool,
    pub detect_module_tampering: bool,
    pub protected_processes: Vec<String>,
    pub max_violations_before_alert: u32,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            monitoring_interval_secs: 30,
            max_baseline_age_secs: 3600,
            detect_inline_hooks: true,
            detect_iat_hooks: true,
            detect_detours: true,
            detect_module_tampering: true,
            protected_processes: vec![
                "lsass.exe".into(),
                "csrss.exe".into(),
                "winlogon.exe".into(),
                "services.exe".into(),
                "smss.exe".into(),
            ],
            max_violations_before_alert: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHash {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleBaseline {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
    pub expected_hash: String,
    pub section_hashes: Vec<SectionHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBaseline {
    pub pid: u32,
    pub process_name: String,
    pub modules: Vec<ModuleBaseline>,
    pub created_at: DateTime<Utc>,
    pub last_checked: DateTime<Utc>,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrityViolationType {
    InlineHook,
    IatHook,
    Detour,
    ModuleTampered,
    CodeCave,
    Trampoline,
    UnexpectedRwx,
    ModuleModified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityViolation {
    pub id: Uuid,
    pub violation_type: IntegrityViolationType,
    pub process_pid: u32,
    pub process_name: String,
    pub module_name: Option<String>,
    pub address: u64,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDetection {
    pub hook_type: IntegrityViolationType,
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub current_bytes: Vec<u8>,
    pub module_name: String,
    pub function_name: Option<String>,
}

pub struct MemoryIntegrityMonitor {
    pub process_baselines: HashMap<u32, ProcessBaseline>,
    pub integrity_violations: Vec<IntegrityViolation>,
    pub config: MemoryConfig,
    total_violations: u64,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn compute_overall_hash(modules: &[ModuleBaseline]) -> String {
    let mut hasher = DefaultHasher::new();
    for module in modules {
        module.expected_hash.hash(&mut hasher);
        for section in &module.section_hashes {
            section.hash.hash(&mut hasher);
        }
    }
    format!("{:016x}", hasher.finish())
}

impl MemoryIntegrityMonitor {
    fn record_violation(&mut self, violation: IntegrityViolation) {
        self.integrity_violations.push(violation);
        self.total_violations += 1;
    }

    pub fn new() -> Self {
        info!("Initializing MemoryIntegrityMonitor with default configuration");
        Self {
            process_baselines: HashMap::new(),
            integrity_violations: Vec::new(),
            config: MemoryConfig::default(),
            total_violations: 0,
        }
    }

    pub fn with_config(config: MemoryConfig) -> Self {
        info!(
            inline_hooks = config.detect_inline_hooks,
            iat_hooks = config.detect_iat_hooks,
            detours = config.detect_detours,
            module_tampering = config.detect_module_tampering,
            "Initializing MemoryIntegrityMonitor with custom configuration"
        );
        Self {
            process_baselines: HashMap::new(),
            integrity_violations: Vec::new(),
            config,
            total_violations: 0,
        }
    }

    pub fn create_baseline(
        &mut self,
        pid: u32,
        process_name: &str,
        modules: Vec<ModuleBaseline>,
    ) -> ProcessBaseline {
        let now = Utc::now();
        let hash = compute_overall_hash(&modules);

        let baseline = ProcessBaseline {
            pid,
            process_name: process_name.to_string(),
            modules,
            created_at: now,
            last_checked: now,
            hash: hash.clone(),
        };

        self.process_baselines.insert(pid, baseline.clone());
        info!(
            pid = pid,
            process = process_name,
            module_count = baseline.modules.len(),
            hash = %hash,
            "Created memory integrity baseline"
        );
        baseline
    }

    pub fn check_integrity(
        &mut self,
        pid: u32,
        current_modules: Vec<ModuleInfo>,
    ) -> Vec<IntegrityViolation> {
        let mut violations = Vec::new();

        let baseline = match self.process_baselines.get(&pid) {
            Some(b) => {
                let age = Utc::now().signed_duration_since(b.created_at);
                if age.num_seconds() as u64 > self.config.max_baseline_age_secs {
                    warn!(
                        pid = pid,
                        age_secs = age.num_seconds(),
                        max_age_secs = self.config.max_baseline_age_secs,
                        "Baseline exceeds maximum age - results may be stale"
                    );
                }
                b.clone()
            }
            None => {
                debug!(pid = pid, "No baseline found for process - skipping integrity check");
                return violations;
            }
        };

        for current_module in &current_modules {
            let baseline_module = match baseline
                .modules
                .iter()
                .find(|m| m.name == current_module.name)
            {
                Some(m) => m,
                None => {
                    debug!(
                        pid = pid,
                        module = %current_module.name,
                        "Module not present in baseline - new module loaded"
                    );
                    continue;
                }
            };

            if self.config.detect_module_tampering {
                for section in &current_module.sections {
                    if let Some(baseline_section) = baseline_module
                        .section_hashes
                        .iter()
                        .find(|s| s.name == section.name)
                    {
                        if baseline_section.hash != section.data_hash {
                            if let Some(v) = self.check_module_tampering(
                                pid,
                                &current_module.name,
                                &section.data_hash,
                                &baseline_section.hash,
                            ) {
                                violations.push(v);
                            }
                        }
                    }
                }

                if baseline_module.expected_hash != current_module.base_address.to_string()
                    && baseline_module.size != current_module.size
                {
                    debug!(
                        pid = pid,
                        module = %current_module.name,
                        baseline_size = baseline_module.size,
                        current_size = current_module.size,
                        "Module size changed - possible tampering"
                    );
                }
            }

            if self.config.detect_iat_hooks {
                let iat_violations =
                    self.detect_iat_hooks(pid, &current_module.name, &current_module.iat_entries);
                violations.extend(iat_violations);
            }
        }

        if let Some(baseline) = self.process_baselines.get_mut(&pid) {
            baseline.last_checked = Utc::now();
        }

        if !violations.is_empty() {
            warn!(
                pid = pid,
                violation_count = violations.len(),
                "Integrity check found violations"
            );
        } else {
            debug!(pid = pid, "Integrity check passed - no violations found");
        }

        violations
    }

    pub fn detect_inline_hooks(
        &mut self,
        pid: u32,
        module_name: &str,
        expected_code: &[u8],
        actual_code: &[u8],
    ) -> Option<IntegrityViolation> {
        if !self.config.detect_inline_hooks {
            return None;
        }

        let check_len = std::cmp::min(expected_code.len(), actual_code.len());
        if check_len < 2 {
            return None;
        }

        if expected_code[..check_len] == actual_code[..check_len] {
            return None;
        }

        let is_jmp_rel32 = actual_code[0] == 0xE9;
        let is_jmp_indirect = check_len >= 2
            && actual_code[0] == 0xFF
            && (actual_code[1] == 0x25 || actual_code[1] == 0x24);
        let is_call_rel32 = actual_code[0] == 0xE8;

        let is_hook = is_jmp_rel32 || is_jmp_indirect || is_call_rel32;

        let violation_type = if is_hook {
            IntegrityViolationType::InlineHook
        } else {
            IntegrityViolationType::ModuleModified
        };

        let (severity, confidence, label) = if is_hook {
            (
                EventSeverity::Critical,
                0.92,
                if is_jmp_rel32 {
                    "JMP rel32 (0xE9)"
                } else if is_jmp_indirect {
                    "JMP [rip+disp32] (0xFF 0x25)"
                } else {
                    "CALL rel32 (0xE8)"
                },
            )
        } else {
            (EventSeverity::Medium, 0.55, "unknown modification")
        };

        let violation = IntegrityViolation {
            id: Uuid::new_v4(),
            violation_type,
            process_pid: pid,
            process_name: String::new(),
            module_name: Some(module_name.to_string()),
            address: 0,
            severity,
            confidence,
            description: format!(
                "{} detected in {}: function prologue modified with {}",
                if is_hook { "Inline hook" } else { "Code modification" },
                module_name,
                label,
            ),
            evidence: vec![
                format!("Expected: {}", hex_encode(&expected_code[..check_len])),
                format!("Actual:   {}", hex_encode(&actual_code[..check_len])),
                format!("Hook instruction: {}", label),
                format!("First byte: 0x{:02X}", actual_code[0]),
            ],
            expected_hash: None,
            actual_hash: None,
            timestamp: Utc::now(),
        };

        if is_hook {
            warn!(
                pid = pid,
                module = module_name,
                instruction = label,
                "Inline hook detected in function prologue"
            );
        } else {
            debug!(
                pid = pid,
                module = module_name,
                "Code modification detected (non-hook pattern)"
            );
        }

        self.record_violation(violation.clone());
        Some(violation)
    }

    pub fn detect_iat_hooks(
        &mut self,
        pid: u32,
        module_name: &str,
        iat_entries: &[IatEntry],
    ) -> Vec<IntegrityViolation> {
        let mut violations = Vec::new();

        if !self.config.detect_iat_hooks {
            return violations;
        }

        for entry in iat_entries {
            if entry.expected_address != 0
                && entry.actual_address != 0
                && entry.expected_address != entry.actual_address
            {
                let violation = IntegrityViolation {
                    id: Uuid::new_v4(),
                    violation_type: IntegrityViolationType::IatHook,
                    process_pid: pid,
                    process_name: String::new(),
                    module_name: Some(module_name.to_string()),
                    address: entry.actual_address,
                    severity: EventSeverity::High,
                    confidence: 0.87,
                    description: format!(
                        "IAT hook in {}: '{}' expected at 0x{:X} redirected to 0x{:X}",
                        module_name, entry.function_name, entry.expected_address, entry.actual_address
                    ),
                    evidence: vec![
                        format!("DLL: {}", entry.dll_name),
                        format!("Function: {}", entry.function_name),
                        format!("Expected: 0x{:X}", entry.expected_address),
                        format!("Actual:   0x{:X}", entry.actual_address),
                        format!(
                            "Delta: 0x{:X}",
                            if entry.actual_address > entry.expected_address {
                                entry.actual_address - entry.expected_address
                            } else {
                                entry.expected_address - entry.actual_address
                            }
                        ),
                    ],
                    expected_hash: None,
                    actual_hash: None,
                    timestamp: Utc::now(),
                };
                warn!(
                    pid = pid,
                    module = module_name,
                    function = %entry.function_name,
                    expected = entry.expected_address,
                    actual = entry.actual_address,
                    "IAT hook detected"
                );
                self.record_violation(violation.clone());
                violations.push(violation);
            }
        }

        violations
    }

    pub fn detect_detours(
        &mut self,
        pid: u32,
        module_name: &str,
        code_region: &[u8],
    ) -> Option<IntegrityViolation> {
        if !self.config.detect_detours || code_region.len() < 2 {
            return None;
        }

        let first = code_region[0];
        let second = code_region[1];

        let (pattern_name, hook_type) = match first {
            0xEB => {
                if code_region.len() >= 2 {
                    let offset = code_region[1] as i8;
                    (
                        format!("short JMP rel8 (0xEB 0x{:02X}, offset {})", second, offset),
                        IntegrityViolationType::Detour,
                    )
                } else {
                    return None;
                }
            }
            0xE9 => {
                if code_region.len() >= 5 {
                    let offset = i32::from_le_bytes([
                        code_region[1],
                        code_region[2],
                        code_region[3],
                        code_region[4],
                    ]);
                    (
                        format!("long JMP rel32 (0xE9, offset {})", offset),
                        IntegrityViolationType::Detour,
                    )
                } else {
                    return None;
                }
            }
            0xE8 => {
                if code_region.len() >= 5 {
                    let offset = i32::from_le_bytes([
                        code_region[1],
                        code_region[2],
                        code_region[3],
                        code_region[4],
                    ]);
                    (
                        format!("CALL rel32 (0xE8, offset {})", offset),
                        IntegrityViolationType::Detour,
                    )
                } else {
                    return None;
                }
            }
            0xFF => {
                if second == 0x25 || second == 0x24 {
                    (
                        format!("indirect JMP (0xFF 0x{:02X})", second),
                        IntegrityViolationType::Detour,
                    )
                } else {
                    return None;
                }
            }
            _ => {
                let magic_patterns: &[(&[u8], &str)] = &[
                    (&[0x48, 0xB8], "mov rax, imm64 (trampoline setup)"),
                    (&[0x48, 0xB9], "mov rcx, imm64 (trampoline setup)"),
                    (&[0x48, 0xBA], "mov rdx, imm64 (trampoline setup)"),
                    (&[0x48, 0xBB], "mov rbx, imm64 (trampoline setup)"),
                    (&[0x68, 0x00, 0x00, 0x00, 0x00, 0xC3], "push 0 / ret (trampoline)"),
                    (&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00], "jmp [rip+0] (null detour)"),
                ];

                for (pattern, name) in magic_patterns {
                    if code_region.len() >= pattern.len()
                        && &code_region[..pattern.len()] == *pattern
                    {
                        return Some(self.build_detour_violation(
                            pid,
                            module_name,
                            code_region,
                            name,
                            IntegrityViolationType::Trampoline,
                            EventSeverity::Critical,
                            0.88,
                        ));
                    }
                }
                return None;
            }
        };

        Some(self.build_detour_violation(
            pid,
            module_name,
            code_region,
            &pattern_name,
            hook_type,
            EventSeverity::High,
            0.85,
        ))
    }

    fn build_detour_violation(
        &mut self,
        pid: u32,
        module_name: &str,
        code_region: &[u8],
        pattern_name: &str,
        hook_type: IntegrityViolationType,
        severity: EventSeverity,
        confidence: f32,
    ) -> IntegrityViolation {
        let snippet_len = std::cmp::min(code_region.len(), 16);
        let violation = IntegrityViolation {
            id: Uuid::new_v4(),
            violation_type: hook_type,
            process_pid: pid,
            process_name: String::new(),
            module_name: Some(module_name.to_string()),
            address: 0,
            severity,
            confidence,
            description: format!(
                "Detour pattern in {}: {} at code region start",
                module_name, pattern_name
            ),
            evidence: vec![
                format!("Pattern: {}", pattern_name),
                format!("First bytes: {}", hex_encode(&code_region[..snippet_len])),
                format!("Region size: {} bytes", code_region.len()),
            ],
            expected_hash: None,
            actual_hash: None,
            timestamp: Utc::now(),
        };
        warn!(
            pid = pid,
            module = module_name,
            pattern = pattern_name,
            "Detour pattern detected in code region"
        );
        self.record_violation(violation.clone());
        violation
    }

    pub fn detect_code_caves(
        &mut self,
        pid: u32,
        module_name: &str,
        section_data: &[u8],
        section_name: &str,
    ) -> Option<IntegrityViolation> {
        if section_data.len() < 32 {
            return None;
        }

        let mut max_run_len: usize = 0;
        let mut max_run_start: usize = 0;
        let mut current_run: usize = 0;
        let mut current_start: usize = 0;

        for (i, &byte) in section_data.iter().enumerate() {
            if byte == 0x90 || byte == 0x00 {
                if current_run == 0 {
                    current_start = i;
                }
                current_run += 1;
            } else {
                if current_run > max_run_len {
                    max_run_len = current_run;
                    max_run_start = current_start;
                }
                current_run = 0;
            }
        }
        if current_run > max_run_len {
            max_run_len = current_run;
            max_run_start = current_start;
        }

        if max_run_len >= 64 {
            let sled_end = max_run_start + max_run_len;
            if sled_end < section_data.len() {
                let remaining = &section_data[sled_end..];
                let has_code = remaining.iter().any(|&b| b != 0x00 && b != 0x90);

                if has_code {
                    let snippet_end = std::cmp::min(sled_end + 16, section_data.len());
                    let violation = IntegrityViolation {
                        id: Uuid::new_v4(),
                        violation_type: IntegrityViolationType::CodeCave,
                        process_pid: pid,
                        process_name: String::new(),
                        module_name: Some(module_name.to_string()),
                        address: 0,
                        severity: EventSeverity::High,
                        confidence: 0.78,
                        description: format!(
                            "Code cave in {} section '{}': {}-byte NOP/zero sled followed by executable code",
                            module_name, section_name, max_run_len
                        ),
                        evidence: vec![
                            format!("Section: {}", section_name),
                            format!("Sled length: {} bytes", max_run_len),
                            format!("Sled offset: 0x{:X}", max_run_start),
                            format!("Code after sled: {} bytes", remaining.len()),
                            format!(
                                "Post-sled bytes: {}",
                                hex_encode(&section_data[sled_end..snippet_end])
                            ),
                        ],
                        expected_hash: None,
                        actual_hash: None,
                        timestamp: Utc::now(),
                    };
                    warn!(
                        pid = pid,
                        module = module_name,
                        section = section_name,
                        sled_len = max_run_len,
                        "Code cave detected: NOP/zero sled followed by code"
                    );
                    self.record_violation(violation.clone());
                    return Some(violation);
                }
            }
        }

        let all_zeros_or_nop = section_data.iter().all(|&b| b == 0x00 || b == 0x90);
        if !all_zeros_or_nop && !section_name.starts_with(".text") && section_data.len() > 256 {
            let nonzero_count = section_data.iter().filter(|&&b| b != 0x00 && b != 0x90).count();
            let ratio = nonzero_count as f64 / section_data.len() as f64;

            if ratio > 0.3 {
                let violation = IntegrityViolation {
                    id: Uuid::new_v4(),
                    violation_type: IntegrityViolationType::UnexpectedRwx,
                    process_pid: pid,
                    process_name: String::new(),
                    module_name: Some(module_name.to_string()),
                    address: 0,
                    severity: EventSeverity::Medium,
                    confidence: 0.6,
                    description: format!(
                        "Suspicious content in non-code section '{}' of {}: {:.1}% non-zero bytes",
                        section_name,
                        module_name,
                        ratio * 100.0
                    ),
                    evidence: vec![
                        format!("Section: {}", section_name),
                        format!("Section size: {} bytes", section_data.len()),
                        format!("Non-zero bytes: {} ({:.1}%)", nonzero_count, ratio * 100.0),
                    ],
                    expected_hash: None,
                    actual_hash: None,
                    timestamp: Utc::now(),
                };
                debug!(
                    pid = pid,
                    module = module_name,
                    section = section_name,
                    ratio = ratio,
                    "Suspicious content in non-code section"
                );
                self.record_violation(violation.clone());
                return Some(violation);
            }
        }

        None
    }

    pub fn check_module_tampering(
        &mut self,
        pid: u32,
        module_name: &str,
        current_hash: &str,
        baseline_hash: &str,
    ) -> Option<IntegrityViolation> {
        if !self.config.detect_module_tampering {
            return None;
        }

        if current_hash == baseline_hash {
            return None;
        }

        let violation = IntegrityViolation {
            id: Uuid::new_v4(),
            violation_type: IntegrityViolationType::ModuleTampered,
            process_pid: pid,
            process_name: String::new(),
            module_name: Some(module_name.to_string()),
            address: 0,
            severity: EventSeverity::High,
            confidence: 0.90,
            description: format!(
                "Module tampered: '{}' hash mismatch between baseline and current state",
                module_name
            ),
            evidence: vec![
                format!("Module: {}", module_name),
                format!("Baseline hash: {}", baseline_hash),
                format!("Current hash:  {}", current_hash),
            ],
            expected_hash: Some(baseline_hash.to_string()),
            actual_hash: Some(current_hash.to_string()),
            timestamp: Utc::now(),
        };
        warn!(
            pid = pid,
            module = module_name,
            baseline = %baseline_hash,
            current = %current_hash,
            "Module tampering detected: hash mismatch"
        );
        self.record_violation(violation.clone());
        Some(violation)
    }

    pub fn update_baseline(&mut self, pid: u32, modules: Vec<ModuleBaseline>) {
        if let Some(baseline) = self.process_baselines.get_mut(&pid) {
            baseline.modules = modules;
            baseline.last_checked = Utc::now();
            baseline.hash = compute_overall_hash(&baseline.modules);
            info!(
                pid = pid,
                module_count = baseline.modules.len(),
                hash = %baseline.hash,
                "Updated memory integrity baseline"
            );
        } else {
            debug!(
                pid = pid,
                "No existing baseline to update - use create_baseline first"
            );
        }
    }

    pub fn violation_count(&self) -> u64 {
        self.total_violations
    }

    pub fn clear_violations(&mut self) {
        let cleared = self.integrity_violations.len();
        self.integrity_violations.clear();
        self.total_violations = 0;
        info!(cleared = cleared, "Cleared all integrity violations");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_hash(name: &str, hash: &str) -> SectionHash {
        SectionHash {
            name: name.to_string(),
            offset: 0,
            size: 0x1000,
            hash: hash.to_string(),
        }
    }

    fn make_module_baseline(name: &str, section_hashes: Vec<SectionHash>) -> ModuleBaseline {
        ModuleBaseline {
            name: name.to_string(),
            path: format!("C:\\Windows\\System32\\{}", name),
            base_address: 0x7FFE0000,
            size: 0x10000,
            expected_hash: format!("hash_{}", name),
            section_hashes,
        }
    }

    fn make_module_info(
        name: &str,
        sections: Vec<ModuleSection>,
        iat_entries: Vec<IatEntry>,
    ) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("C:\\Windows\\System32\\{}", name),
            base_address: 0x7FFE0000,
            size: 0x10000,
            sections,
            iat_entries,
        }
    }

    fn make_module_section(name: &str, hash: &str, executable: bool) -> ModuleSection {
        ModuleSection {
            name: name.to_string(),
            offset: 0,
            size: 0x1000,
            data_hash: hash.to_string(),
            executable,
        }
    }

    #[test]
    fn test_new_monitor() {
        let monitor = MemoryIntegrityMonitor::new();
        assert_eq!(monitor.violation_count(), 0);
        assert!(monitor.integrity_violations.is_empty());
        assert!(monitor.process_baselines.is_empty());
        assert!(monitor.config.detect_inline_hooks);
        assert!(monitor.config.detect_iat_hooks);
        assert!(monitor.config.detect_detours);
        assert!(monitor.config.detect_module_tampering);
        assert_eq!(monitor.config.monitoring_interval_secs, 30);
        assert_eq!(monitor.config.max_baseline_age_secs, 3600);
        assert_eq!(monitor.config.max_violations_before_alert, 1);
        assert!(monitor
            .config
            .protected_processes
            .contains(&"lsass.exe".to_string()));
        assert!(monitor
            .config
            .protected_processes
            .contains(&"csrss.exe".to_string()));
        assert!(monitor
            .config
            .protected_processes
            .contains(&"winlogon.exe".to_string()));
    }

    #[test]
    fn test_create_baseline_and_check_integrity_match() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let baseline_sections = vec![make_section_hash(".text", "aaa111")];
        let module_baseline = make_module_baseline("kernel32.dll", baseline_sections);
        let baseline = monitor.create_baseline(100, "test.exe", vec![module_baseline]);
        assert_eq!(baseline.pid, 100);
        assert_eq!(baseline.process_name, "test.exe");
        assert_eq!(baseline.modules.len(), 1);

        let current_sections = vec![make_module_section(".text", "aaa111", true)];
        let module_info = make_module_info("kernel32.dll", current_sections, vec![]);

        let violations = monitor.check_integrity(100, vec![module_info]);
        assert!(
            violations.is_empty(),
            "Expected no violations when current matches baseline, got {:?}",
            violations
        );
    }

    #[test]
    fn test_detect_inline_hooks_clean_code() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let clean_prologue: Vec<u8> = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC];
        let result = monitor.detect_inline_hooks(
            100,
            "kernel32.dll",
            &clean_prologue,
            &clean_prologue,
        );
        assert!(result.is_none(), "Clean matching prologues should not trigger detection");
    }

    #[test]
    fn test_detect_inline_hooks_hooked_code() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let original: Vec<u8> = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC];
        let hooked: Vec<u8> = vec![0xE9, 0x78, 0x56, 0x34, 0x12, 0x48, 0x83, 0xEC];

        let result = monitor.detect_inline_hooks(100, "kernel32.dll", &original, &hooked);
        assert!(result.is_some(), "Hooked prologue should trigger detection");

        let violation = result.unwrap();
        assert_eq!(violation.violation_type, IntegrityViolationType::InlineHook);
        assert_eq!(violation.severity, EventSeverity::Critical);
        assert!(violation.confidence > 0.8);
        assert!(violation.description.contains("Inline hook"));
        assert_eq!(violation.process_pid, 100);
        assert_eq!(violation.module_name.as_deref(), Some("kernel32.dll"));
    }

    #[test]
    fn test_detect_inline_hooks_indirect_jmp() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let original: Vec<u8> = vec![0x48, 0x83, 0xEC, 0x20, 0x33, 0xDB, 0x45, 0x33];
        let hooked: Vec<u8> = vec![0xFF, 0x25, 0x78, 0x56, 0x34, 0x12, 0x45, 0x33];

        let result = monitor.detect_inline_hooks(100, "ntdll.dll", &original, &hooked);
        assert!(result.is_some());
        let violation = result.unwrap();
        assert_eq!(violation.violation_type, IntegrityViolationType::InlineHook);
        assert!(violation.description.contains("0xFF 0x25"));
    }

    #[test]
    fn test_detect_inline_hooks_disabled() {
        let config = MemoryConfig {
            detect_inline_hooks: false,
            ..MemoryConfig::default()
        };
        let mut monitor = MemoryIntegrityMonitor::with_config(config);

        let original: Vec<u8> = vec![0x48, 0x89, 0x5C, 0x24, 0x08];
        let hooked: Vec<u8> = vec![0xE9, 0x78, 0x56, 0x34, 0x12];

        let result = monitor.detect_inline_hooks(100, "test.dll", &original, &hooked);
        assert!(result.is_none(), "Detection disabled should return None");
    }

    #[test]
    fn test_detect_detours_long_jmp() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let code_region: Vec<u8> = vec![0xE9, 0x78, 0x56, 0x34, 0x12, 0x90, 0x90, 0x90];
        let result = monitor.detect_detours(200, "evil.dll", &code_region);
        assert!(result.is_some(), "Long JMP should be detected as detour");

        let violation = result.unwrap();
        assert_eq!(violation.violation_type, IntegrityViolationType::Detour);
        assert_eq!(violation.severity, EventSeverity::High);
        assert!(violation.description.contains("Detour pattern"));
        assert_eq!(violation.process_pid, 200);
    }

    #[test]
    fn test_detect_detours_short_jmp() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let code_region: Vec<u8> = vec![0xEB, 0x10, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let result = monitor.detect_detours(300, "hook.dll", &code_region);
        assert!(result.is_some());

        let violation = result.unwrap();
        assert_eq!(violation.violation_type, IntegrityViolationType::Detour);
        assert!(violation.description.contains("short JMP"));
    }

    #[test]
    fn test_detect_detours_no_pattern() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let code_region: Vec<u8> = vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC];
        let result = monitor.detect_detours(100, "clean.dll", &code_region);
        assert!(result.is_none(), "Normal prologue should not trigger detour detection");
    }

    #[test]
    fn test_detect_detours_disabled() {
        let config = MemoryConfig {
            detect_detours: false,
            ..MemoryConfig::default()
        };
        let mut monitor = MemoryIntegrityMonitor::with_config(config);

        let code_region: Vec<u8> = vec![0xE9, 0x78, 0x56, 0x34, 0x12];
        let result = monitor.detect_detours(100, "test.dll", &code_region);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_code_caves_nop_sled() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let mut section_data = vec![0x00u8; 128];
        section_data.extend_from_slice(&[0x90; 64]);
        section_data.extend_from_slice(&[0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x83, 0xEC]);

        let result = monitor.detect_code_caves(100, "payload.dll", &section_data, ".rsrc");
        assert!(result.is_some(), "NOP sled followed by code should be detected");

        let violation = result.unwrap();
        assert_eq!(violation.violation_type, IntegrityViolationType::CodeCave);
        assert_eq!(violation.severity, EventSeverity::High);
        assert!(violation.description.contains("Code cave"));
        assert!(violation.description.contains(".rsrc"));
    }

    #[test]
    fn test_detect_code_caves_no_cave() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let section_data: Vec<u8> = (0..256).map(|i| (i % 251) as u8 + 1).collect();
        let result = monitor.detect_code_caves(100, "clean.dll", &section_data, ".text");
        assert!(result.is_none(), "Dense code section should not trigger cave detection");
    }

    #[test]
    fn test_check_module_tampering_detects_mismatch() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let result = monitor.check_module_tampering(
            100,
            "ntdll.dll",
            "aabbccdd",
            "11223344",
        );
        assert!(result.is_some(), "Hash mismatch should be detected");

        let violation = result.unwrap();
        assert_eq!(violation.violation_type, IntegrityViolationType::ModuleTampered);
        assert_eq!(violation.severity, EventSeverity::High);
        assert!(violation.expected_hash.is_some());
        assert!(violation.actual_hash.is_some());
        assert_eq!(violation.expected_hash.as_deref(), Some("11223344"));
        assert_eq!(violation.actual_hash.as_deref(), Some("aabbccdd"));
    }

    #[test]
    fn test_check_module_tampering_no_violation_on_match() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let result = monitor.check_module_tampering(
            100,
            "ntdll.dll",
            "aabbccdd",
            "aabbccdd",
        );
        assert!(result.is_none(), "Matching hashes should not trigger detection");
    }

    #[test]
    fn test_check_module_tampering_disabled() {
        let config = MemoryConfig {
            detect_module_tampering: false,
            ..MemoryConfig::default()
        };
        let mut monitor = MemoryIntegrityMonitor::with_config(config);

        let result = monitor.check_module_tampering(100, "test.dll", "aa", "bb");
        assert!(result.is_none());
    }

    #[test]
    fn test_clear_violations() {
        let mut monitor = MemoryIntegrityMonitor::new();

        monitor.check_module_tampering(100, "a.dll", "aa", "bb");
        monitor.check_module_tampering(100, "b.dll", "cc", "dd");
        assert_eq!(monitor.violation_count(), 2);
        assert_eq!(monitor.integrity_violations.len(), 2);

        monitor.clear_violations();
        assert_eq!(monitor.violation_count(), 0);
        assert!(monitor.integrity_violations.is_empty());
    }

    #[test]
    fn test_violation_count_increments() {
        let mut monitor = MemoryIntegrityMonitor::new();
        assert_eq!(monitor.violation_count(), 0);

        monitor.check_module_tampering(100, "a.dll", "aa", "bb");
        assert_eq!(monitor.violation_count(), 1);

        monitor.check_module_tampering(100, "b.dll", "cc", "dd");
        assert_eq!(monitor.violation_count(), 2);

        let original: Vec<u8> = vec![0x48, 0x89, 0x5C, 0x24, 0x08];
        let hooked: Vec<u8> = vec![0xE9, 0x78, 0x56, 0x34, 0x12];
        monitor.detect_inline_hooks(100, "c.dll", &original, &hooked);
        assert_eq!(monitor.violation_count(), 3);
    }

    #[test]
    fn test_with_config_custom_settings() {
        let config = MemoryConfig {
            monitoring_interval_secs: 60,
            max_baseline_age_secs: 7200,
            detect_inline_hooks: false,
            detect_iat_hooks: false,
            detect_detours: false,
            detect_module_tampering: false,
            protected_processes: vec!["lsass.exe".into()],
            max_violations_before_alert: 5,
        };
        let monitor = MemoryIntegrityMonitor::with_config(config);

        assert_eq!(monitor.config.monitoring_interval_secs, 60);
        assert_eq!(monitor.config.max_baseline_age_secs, 7200);
        assert!(!monitor.config.detect_inline_hooks);
        assert!(!monitor.config.detect_iat_hooks);
        assert!(!monitor.config.detect_detours);
        assert!(!monitor.config.detect_module_tampering);
        assert_eq!(monitor.config.protected_processes.len(), 1);
        assert_eq!(monitor.config.max_violations_before_alert, 5);
    }

    #[test]
    fn test_detect_iat_hooks_mismatched_addresses() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let entries = vec![
            IatEntry {
                function_name: "CreateFileW".to_string(),
                dll_name: "kernel32.dll".to_string(),
                expected_address: 0x7FFE1000,
                actual_address: 0x7FFE1000,
            },
            IatEntry {
                function_name: "ReadProcessMemory".to_string(),
                dll_name: "kernel32.dll".to_string(),
                expected_address: 0x7FFE2000,
                actual_address: 0x7FFE9999,
            },
            IatEntry {
                function_name: "VirtualAlloc".to_string(),
                dll_name: "kernel32.dll".to_string(),
                expected_address: 0x7FFE3000,
                actual_address: 0x7FFEAAAA,
            },
        ];

        let violations = monitor.detect_iat_hooks(100, "payload.dll", &entries);
        assert_eq!(violations.len(), 2, "Should detect 2 IAT hooks (mismatched addresses)");

        for v in &violations {
            assert_eq!(v.violation_type, IntegrityViolationType::IatHook);
            assert_eq!(v.severity, EventSeverity::High);
            assert!(v.description.contains("IAT hook"));
        }

        let func_names: Vec<&str> = violations
            .iter()
            .filter_map(|v| {
                v.evidence
                    .iter()
                    .find(|e| e.starts_with("Function:"))
                    .map(|e| e.as_str())
            })
            .collect();
        assert!(func_names.iter().any(|n| n.contains("ReadProcessMemory")));
        assert!(func_names.iter().any(|n| n.contains("VirtualAlloc")));
    }

    #[test]
    fn test_detect_iat_hooks_all_match() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let entries = vec![
            IatEntry {
                function_name: "CreateFileW".to_string(),
                dll_name: "kernel32.dll".to_string(),
                expected_address: 0x7FFE1000,
                actual_address: 0x7FFE1000,
            },
        ];

        let violations = monitor.detect_iat_hooks(100, "clean.dll", &entries);
        assert!(violations.is_empty(), "Matching IAT entries should not trigger detection");
    }

    #[test]
    fn test_integrity_check_with_iat_hook() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let baseline_sections = vec![make_section_hash(".text", "aaa111")];
        monitor.create_baseline(
            100,
            "test.exe",
            vec![make_module_baseline("target.dll", baseline_sections)],
        );

        let current_sections = vec![make_module_section(".text", "aaa111", true)];
        let iat_entries = vec![IatEntry {
            function_name: "NtWriteVirtualMemory".to_string(),
            dll_name: "ntdll.dll".to_string(),
            expected_address: 0x7FFE5000,
            actual_address: 0x7FFEEEEE,
        }];
        let module_info = make_module_info("target.dll", current_sections, iat_entries);

        let violations = monitor.check_integrity(100, vec![module_info]);
        assert_eq!(violations.len(), 1, "Should detect the IAT hook");
        assert_eq!(violations[0].violation_type, IntegrityViolationType::IatHook);
    }

    #[test]
    fn test_baseline_stored_and_retrieved() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let sections = vec![make_section_hash(".text", "abc")];
        monitor.create_baseline(10, "proc.exe", vec![make_module_baseline("mod.dll", sections)]);

        assert!(monitor.process_baselines.contains_key(&10));
        let baseline = monitor.process_baselines.get(&10).unwrap();
        assert_eq!(baseline.pid, 10);
        assert_eq!(baseline.process_name, "proc.exe");
        assert_eq!(baseline.modules.len(), 1);
        assert_eq!(baseline.modules[0].name, "mod.dll");
    }

    #[test]
    fn test_update_baseline() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let sections = vec![make_section_hash(".text", "old_hash")];
        monitor.create_baseline(
            100,
            "test.exe",
            vec![make_module_baseline("mod.dll", sections)],
        );

        let old_hash = monitor.process_baselines[&100].hash.clone();

        let new_sections = vec![make_section_hash(".text", "new_hash")];
        let new_modules = vec![make_module_baseline("mod.dll", new_sections)];
        monitor.update_baseline(100, new_modules);

        let updated = &monitor.process_baselines[&100];
        assert_ne!(updated.hash, old_hash, "Hash should change after update");
    }

    #[test]
    fn test_no_baseline_returns_empty() {
        let mut monitor = MemoryIntegrityMonitor::new();

        let module_info = make_module_info("unknown.dll", vec![], vec![]);
        let violations = monitor.check_integrity(999, vec![module_info]);
        assert!(violations.is_empty(), "No baseline should return empty violations");
    }
}
