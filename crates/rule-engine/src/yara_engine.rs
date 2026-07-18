use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::info;

use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum YaraStringType {
    Text,
    Hex,
    Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub value: String,
    #[serde(rename = "type")]
    pub string_type: YaraStringType,
    pub modifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: EventSeverity,
    pub author: String,
    pub date: String,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
    pub condition: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub rule_id: String,
    pub bytecode: Vec<u8>,
    pub compiled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub offset: usize,
    pub matched_string: String,
    pub matched_data: Vec<u8>,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStats {
    pub total_rules: usize,
    pub compiled_rules: usize,
    pub matches: u64,
    pub scan_time_avg_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanStats {
    pub total_scans: u64,
    pub rate_limited_scans: u64,
    pub avg_scan_time_ns: u64,
}

struct TokenBucket {
    capacity: u64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_per_sec: u64) -> Self {
        Self {
            capacity: max_per_sec,
            tokens: max_per_sec as f64,
            refill_per_sec: max_per_sec as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity as f64);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct YaraEngine {
    rules: Vec<YaraRule>,
    compiled_rules: HashMap<String, CompiledRule>,
    stats: YaraStats,
    scan_stats: Arc<std::sync::Mutex<ScanStats>>,
    rate_limiter: Arc<std::sync::Mutex<TokenBucket>>,
}

fn find_pattern(data: &[u8], pattern: &[u8], nocase: bool) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    if nocase {
        let limit = data.len() - pattern.len();
        for offset in 0..=limit {
            if data[offset..offset + pattern.len()]
                .iter()
                .zip(pattern.iter())
                .all(|(d, p)| d.eq_ignore_ascii_case(p))
            {
                return Some(offset);
            }
        }
    } else {
        for offset in 0..=data.len() - pattern.len() {
            if &data[offset..offset + pattern.len()] == pattern {
                return Some(offset);
            }
        }
    }
    None
}

impl YaraEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_rules: HashMap::new(),
            stats: YaraStats {
                total_rules: 0,
                compiled_rules: 0,
                matches: 0,
                scan_time_avg_us: 0,
            },
            scan_stats: Arc::new(std::sync::Mutex::new(ScanStats::default())),
            rate_limiter: Arc::new(std::sync::Mutex::new(TokenBucket::new(1000))),
        }
    }

    pub fn add_rule(&mut self, rule: YaraRule) {
        let rule_id = rule.id.clone();
        self.compile_rule(&rule);
        self.rules.push(rule);
        self.stats.total_rules = self.rules.len();
        info!(rule_id = %rule_id, "Added YARA rule");
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.compiled_rules.remove(rule_id);
        self.stats.total_rules = self.rules.len();
        self.stats.compiled_rules = self.compiled_rules.len();
        before != self.rules.len()
    }

    pub fn scan_data(&mut self, data: &[u8]) -> Vec<YaraMatch> {
        let start = std::time::Instant::now();

        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if !limiter.try_acquire() {
                let mut stats = self.scan_stats.lock().unwrap();
                stats.rate_limited_scans += 1;
                return Vec::new();
            }
        }

        let mut matches = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if !self.compiled_rules.contains_key(&rule.id) {
                continue;
            }
            for yara_string in &rule.strings {
                match yara_string.string_type {
                    YaraStringType::Text => {
                        let needle = yara_string.value.as_bytes();
                        let nocase = yara_string.modifiers.iter().any(|m| m == "nocase");
                        if let Some(offset) = find_pattern(data, needle, nocase) {
                            matches.push(YaraMatch {
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                offset,
                                matched_string: yara_string.identifier.clone(),
                                matched_data: data[offset..offset + needle.len()].to_vec(),
                                severity: rule.severity.clone(),
                            });
                            break;
                        }
                    }
                    YaraStringType::Regex => {
                        if let Ok(re) = regex::Regex::new(&yara_string.value) {
                            let text = String::from_utf8_lossy(data);
                            if let Some(mat) = re.find(&text) {
                                matches.push(YaraMatch {
                                    rule_id: rule.id.clone(),
                                    rule_name: rule.name.clone(),
                                    offset: mat.start(),
                                    matched_string: yara_string.identifier.clone(),
                                    matched_data: mat.as_str().as_bytes().to_vec(),
                                    severity: rule.severity.clone(),
                                });
                                break;
                            }
                        }
                    }
                    YaraStringType::Hex => {
                        let cleaned: String = yara_string.value.chars().filter(|c| !c.is_whitespace()).collect();
                        if let Ok(decoded) = hex::decode(&cleaned) {
                            if let Some(offset) = find_pattern(data, &decoded, false) {
                                matches.push(YaraMatch {
                                    rule_id: rule.id.clone(),
                                    rule_name: rule.name.clone(),
                                    offset,
                                    matched_string: yara_string.identifier.clone(),
                                    matched_data: data[offset..offset + decoded.len()].to_vec(),
                                    severity: rule.severity.clone(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        let elapsed_ns = start.elapsed().as_nanos() as u64;
        let elapsed_us = start.elapsed().as_micros() as u64;
        self.stats.matches += matches.len() as u64;
        if self.stats.scan_time_avg_us == 0 {
            self.stats.scan_time_avg_us = elapsed_us;
        } else {
            self.stats.scan_time_avg_us = (self.stats.scan_time_avg_us + elapsed_us) / 2;
        }

        {
            let mut stats = self.scan_stats.lock().unwrap();
            stats.total_scans += 1;
            if stats.avg_scan_time_ns == 0 {
                stats.avg_scan_time_ns = elapsed_ns;
            } else {
                stats.avg_scan_time_ns = (stats.avg_scan_time_ns + elapsed_ns) / 2;
            }
        }

        matches
    }

    pub fn scan_text(&mut self, text: &str) -> Vec<YaraMatch> {
        self.scan_data(text.as_bytes())
    }

    pub fn compile_rule(&mut self, rule: &YaraRule) {
        let bytecode = format!("compiled:{}", rule.id).into_bytes();
        self.compiled_rules.insert(
            rule.id.clone(),
            CompiledRule {
                rule_id: rule.id.clone(),
                bytecode,
                compiled_at: Utc::now(),
            },
        );
        self.stats.compiled_rules = self.compiled_rules.len();
    }

    pub fn list_rules(&self) -> &[YaraRule] {
        &self.rules
    }

    pub fn get_stats(&self) -> &YaraStats {
        &self.stats
    }

    pub fn get_scan_stats(&self) -> ScanStats {
        self.scan_stats.lock().unwrap().clone()
    }

    pub fn load_default_rules(&mut self) {
        let rules = vec![
            // -- Malware Families --
            YaraRule { id: "malware_emotet".into(), name: "Emotet Banker".into(), description: "Detects Emotet banking trojan indicators".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "emotet".into(), "banker".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "HRMLcZl1".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "clb.dll".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "http://".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_trickbot".into(), name: "TrickBot".into(), description: "Detects TrickBot malware patterns".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "trickbot".into(), "banker".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "GroupPolicy".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "ModulesConfig".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "InjectDll".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_ryuk".into(), name: "Ryuk Ransomware".into(), description: "Detects Ryuk ransomware".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "ransomware".into(), "ryuk".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "UNIQUE_ID_FOR_DECRYPTOR".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "3.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "app_config.json".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_conti".into(), name: "Conti Ransomware".into(), description: "Detects Conti ransomware".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "ransomware".into(), "conti".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "CONTI_README".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "polices are expired".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_lockbit".into(), name: "LockBit Ransomware".into(), description: "Detects LockBit ransomware".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "ransomware".into(), "lockbit".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "lockbit".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "All your files are stolen".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: ".lockbit".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_cobalt_strike".into(), name: "Cobalt Strike Beacon".into(), description: "Detects Cobalt Strike beacon artifacts".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "cobalt_strike".into(), "c2".into(), "mitre:T1071".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "beacon.dll".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "%d is an x86 OR x64 bit OS".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "api.php?f=id".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s4".into(), value: "\\pipe\\msagent_*".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_mimikatz".into(), name: "Mimikatz Credential Dump".into(), description: "Detects Mimikatz credential harvesting tool".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "mimikatz".into(), "credentials".into(), "mitre:T1003".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "gentilkiwi".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "mimidrv".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "mimilib".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s4".into(), value: "sekurlsa::logonpasswords".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_qakbot".into(), name: "QakBot".into(), description: "Detects QakBot/QBot malware".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "qakbot".into(), "banker".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "C:\\ProgramData\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "\\AppData\\Local\\Temp\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*) and filesize < 2MB".into(), enabled: true },
            YaraRule { id: "malware_icedid".into(), name: "IcedID Loader".into(), description: "Detects IcedID/BokBot loader".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "icedid".into(), "loader".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "license.dat".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "GET /sync=".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_dridex".into(), name: "Dridex".into(), description: "Detects Dridex banking trojan".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "dridex".into(), "banker".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "GroupTag".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "SessionLoader".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            YaraRule { id: "malware_formbook".into(), name: "Formbook".into(), description: "Detects Formbook/Agent Tesla info stealer".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["malware".into(), "formbook".into(), "stealer".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "xClient".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "klg_hk".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            // -- Process Injection --
            YaraRule { id: "inject_createremotethread".into(), name: "Process Injection - CreateRemoteThread".into(), description: "Detects CreateRemoteThread API usage for process injection".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["injection".into(), "mitre:T1055".into()], strings: vec![YaraString { identifier: "$api1".into(), value: "CreateRemoteThread".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api2".into(), value: "VirtualAllocEx".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api3".into(), value: "WriteProcessMemory".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($api*)".into(), enabled: true },
            YaraRule { id: "inject_process_hollowing".into(), name: "Process Hollowing".into(), description: "Detects process hollowing indicators".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["injection".into(), "mitre:T1055.012".into()], strings: vec![YaraString { identifier: "$api1".into(), value: "NtUnmapViewOfSection".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api2".into(), value: "ZwUnmapViewOfSection".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api3".into(), value: "SetThreadContext".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($api*)".into(), enabled: true },
            YaraRule { id: "inject_apc_queue".into(), name: "APC Queue Injection".into(), description: "Detects APC injection via QueueUserAPC".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["injection".into(), "mitre:T1055".into()], strings: vec![YaraString { identifier: "$api1".into(), value: "QueueUserAPC".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api2".into(), value: "NtQueueApcThread".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($api*)".into(), enabled: true },
            YaraRule { id: "inject_reflective_dll".into(), name: "Reflective DLL Loading".into(), description: "Detects reflective DLL injection patterns".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["injection".into(), "mitre:T1620".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "ReflectiveLoader".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "0xE8A3".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "inject_appinit_dlls".into(), name: "AppInit_DLLs Persistence".into(), description: "Detects AppInit_DLLs registry modification for persistence".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["persistence".into(), "mitre:T1546.010".into()], strings: vec![YaraString { identifier: "$reg".into(), value: "AppInit_DLLs".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$reg2".into(), value: "LoadAppInit_DLLs".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($reg*)".into(), enabled: true },
            // -- Credential Access --
            YaraRule { id: "cred_lsass_dump".into(), name: "LSASS Memory Dump".into(), description: "Detects LSASS credential dumping tools".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["credentials".into(), "mitre:T1003.001".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "lsass.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "MiniDumpWriteDump".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "procdump".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s4".into(), value: "comsvcs.dll".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "cred_dcsync".into(), name: "DCSync Attack".into(), description: "Detects DCSync attack patterns for AD credential theft".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["credentials".into(), "mitre:T1003.006".into(), "active_directory".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "DRSUAPI".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "DsGetNCChanges".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "Directory Replication".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "cred_token_theft".into(), name: "Token Theft".into(), description: "Detects Windows token impersonation/theft".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["credentials".into(), "mitre:T1134".into()], strings: vec![YaraString { identifier: "$api1".into(), value: "ImpersonateLoggedOnUser".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api2".into(), value: "DuplicateTokenEx".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api3".into(), value: "SetThreadToken".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($api*)".into(), enabled: true },
            // -- Defense Evasion --
            YaraRule { id: "evasion_amsi_bypass".into(), name: "AMSI Bypass".into(), description: "Detects AMSI bypass techniques".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["evasion".into(), "mitre:T1562.001".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "AmsiScanBuffer".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "amsi.dll".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "amsiInitFailed".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s4".into(), value: "SetProcessMitigationPolicy".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "evasion_etw_patch".into(), name: "ETW Patching".into(), description: "Detects Event Tracing for Windows patching to evade logging".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["evasion".into(), "mitre:T1562.006".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "EtwEventWrite".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "NtTraceControl".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "evasion_unhooking".into(), name: "API Unhooking".into(), description: "Detects ntdll unhooking to restore syscall stubs".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["evasion".into(), "mitre:T1562.001".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "NtProtectVirtualMemory".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "NtReadVirtualMemory".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            YaraRule { id: "evasion_timestomp".into(), name: "Timestomping".into(), description: "Detects file timestamp manipulation".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["evasion".into(), "mitre:T1070.006".into()], strings: vec![YaraString { identifier: "$api1".into(), value: "SetFileTime".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$api2".into(), value: "SetFileAttributes".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($api*)".into(), enabled: true },
            YaraRule { id: "evasion_signed_proxy".into(), name: "Signed Binary Proxy Execution".into(), description: "Detects use of signed binaries for proxy execution (mshta, regsvr32, rundll32)".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["evasion".into(), "mitre:T1218".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "mshta.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "regsvr32.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "rundll32.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            // -- Persistence --
            YaraRule { id: "persist_scheduled_task".into(), name: "Scheduled Task Creation".into(), description: "Detects suspicious scheduled task creation".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["persistence".into(), "mitre:T1053.005".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "schtasks /create".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "ScheduledTask".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "Register-ScheduledTask".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "persist_service_create".into(), name: "Service Creation".into(), description: "Detects suspicious service installation".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["persistence".into(), "mitre:T1543.003".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "sc create".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "New-Service".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "Win32_Service".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "persist_run_key".into(), name: "Registry Run Key".into(), description: "Detects persistence via registry Run/RunOnce keys".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["persistence".into(), "mitre:T1547.001".into()], strings: vec![YaraString { identifier: "$reg1".into(), value: "\\CurrentVersion\\Run\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$reg2".into(), value: "\\CurrentVersion\\RunOnce\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($reg*)".into(), enabled: true },
            YaraRule { id: "persist_wmi_sub".into(), name: "WMI Event Subscription".into(), description: "Detects WMI persistence via event subscription".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["persistence".into(), "mitre:T1546.003".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "__EventFilter".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "CommandLineEventConsumer".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "__FilterToConsumerBinding".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            // -- Discovery --
            YaraRule { id: "disc_whoami".into(), name: "Whoami Enumeration".into(), description: "Detects system enumeration commands".into(), severity: EventSeverity::Low, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["discovery".into(), "mitre:T1033".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "whoami /all".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "whoami /priv".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s3".into(), value: "net group \"Domain Admins\"".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "disc_nltest".into(), name: "Domain Discovery".into(), description: "Detects domain reconnaissance commands".into(), severity: EventSeverity::Low, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["discovery".into(), "mitre:T1482".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "nltest /domain_trusts".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "net group \"Enterprise Admins\"".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s3".into(), value: "dsquery".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "disc_systeminfo".into(), name: "System Information Discovery".into(), description: "Detects systeminfo and similar discovery commands".into(), severity: EventSeverity::Low, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["discovery".into(), "mitre:T1082".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "systeminfo".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "ipconfig /all".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }], condition: "1 of ($s*)".into(), enabled: true },
            // -- Script Abuse --
            YaraRule { id: "script_ps_obfuscated".into(), name: "PowerShell Obfuscation".into(), description: "Detects obfuscated PowerShell commands".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["script".into(), "mitre:T1059.001".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "powershell -enc".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "powershell -nop".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s3".into(), value: "DownloadString".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s4".into(), value: "IEX(".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s5".into(), value: "Invoke-Expression".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "script_office_macro".into(), name: "Office Macro Execution".into(), description: "Detects malicious Office macro patterns".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["script".into(), "mitre:T1059.005".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "Auto_Open".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "Document_Open".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "Shell(".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s4".into(), value: "WScript.Shell".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s5".into(), value: "CreateObject".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "script_hta_abuse".into(), name: "HTA/WSF Abuse".into(), description: "Detects HTML Application or Windows Script File abuse".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["script".into(), "mitre:T1218.005".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "mshta.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "wscript.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "cscript.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "script_certutil".into(), name: "Certutil Download".into(), description: "Detects certutil being used to download files".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["script".into(), "mitre:T1105".into(), "mitre:T1218.030".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "certutil -urlcache".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "certutil -decode".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s3".into(), value: "certutil.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            // -- Network / C2 --
            YaraRule { id: "net_dns_tunnel".into(), name: "DNS Tunneling".into(), description: "Detects DNS tunneling for data exfiltration".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["network".into(), "mitre:T1071.004".into(), "exfiltration".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "nslookup -type=TXT".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "dnscat".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "iodine".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "net_beacon".into(), name: "C2 Beacon Pattern".into(), description: "Detects command-and-control beacon indicators".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["network".into(), "c2".into(), "mitre:T1573".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "sleep(".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "jitter".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "checkin".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            YaraRule { id: "net_encoded_cmd".into(), name: "Encoded Command Execution".into(), description: "Detects base64-encoded command execution".into(), severity: EventSeverity::High, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["network".into(), "mitre:T1059.001".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "FromBase64String".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "-EncodedCommand".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "[Convert]::FromBase64".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            // -- Lateral Movement --
            YaraRule { id: "lateral_psexec".into(), name: "PsExec Lateral Movement".into(), description: "Detects PsExec usage for lateral movement".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["lateral_movement".into(), "mitre:T1021.002".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "psexec".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "\\PSEXESVC".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "PsExec.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "lateral_wmi_exec".into(), name: "WMI Execution".into(), description: "Detects WMI-based remote execution".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["lateral_movement".into(), "mitre:T1047".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "Win32_Process".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "Create()".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s3".into(), value: "Invoke-WmiMethod".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "2 of ($s*)".into(), enabled: true },
            // -- Exfiltration --
            YaraRule { id: "exfil_large_upload".into(), name: "Large Data Upload".into(), description: "Detects potential data exfiltration via large uploads".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["exfiltration".into(), "mitre:T1041".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "curl -X POST".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "Invoke-WebRequest -Method Post".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
            YaraRule { id: "exfil_http_post".into(), name: "HTTP POST Exfiltration".into(), description: "Detects HTTP POST-based data exfiltration".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["exfiltration".into(), "mitre:T1048".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "Content-Type: multipart/form-data".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$s2".into(), value: "curl.exe".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "all of ($s*)".into(), enabled: true },
            // -- Suspicious Indicators --
            YaraRule { id: "sus_high_entropy".into(), name: "High Entropy Payload".into(), description: "Detects high-entropy strings indicating encrypted/compressed data".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["suspicious".into(), "obfuscation".into()], strings: vec![YaraString { identifier: "$b64".into(), value: "TVqQAAMAAAAEAAAA".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$b642".into(), value: "UEsDBBQAAAAI".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$b643".into(), value: "H4sIAAAAA".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($b64*)".into(), enabled: true },
            YaraRule { id: "sus_temp_folder".into(), name: "Suspicious Temp Execution".into(), description: "Detects executable running from temp directories".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["suspicious".into(), "mitre:T1059".into()], strings: vec![YaraString { identifier: "$p1".into(), value: "\\Temp\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$p2".into(), value: "\\AppData\\Local\\Temp\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }, YaraString { identifier: "$p3".into(), value: "\\Windows\\Temp\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($p*)".into(), enabled: true },
            YaraRule { id: "sus_ransom_note".into(), name: "Ransomware Note".into(), description: "Detects ransomware ransom note patterns".into(), severity: EventSeverity::Critical, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["ransomware".into(), "mitre:T1486".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "your files have been encrypted".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s2".into(), value: "pay the ransom".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s3".into(), value: "bitcoin wallet".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }, YaraString { identifier: "$s4".into(), value: "decrypt your files".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] }], condition: "2 of ($s*)".into(), enabled: true },
            YaraRule { id: "sus_hidden_folder".into(), name: "Hidden Folder Execution".into(), description: "Detects execution from hidden folders".into(), severity: EventSeverity::Medium, author: "RoyalSecurity".into(), date: "2025-01-01".into(), tags: vec!["suspicious".into(), "evasion".into()], strings: vec![YaraString { identifier: "$s1".into(), value: "\\\\.\\".into(), string_type: YaraStringType::Text, modifiers: vec![] }], condition: "1 of ($s*)".into(), enabled: true },
        ];

        for rule in rules {
            self.add_rule(rule);
        }
        info!(count = self.rules.len(), "Loaded built-in YARA rules");
    }




    pub fn import_rules_from_yaml(
        &mut self,
        yaml: &str,
    ) -> Result<Vec<YaraRule>, Box<dyn std::error::Error + Send + Sync>> {
        let docs = yaml_rust2::YamlLoader::load_from_str(yaml)?;
        let mut imported = Vec::new();

        for doc in docs {
            if let Some(arr) = doc.as_vec() {
                for item in arr {
                    if let Some(rule) = Self::parse_yaml_rule(item) {
                        imported.push(rule);
                    }
                }
            } else if let Some(rule) = Self::parse_yaml_rule(&doc) {
                imported.push(rule);
            }
        }

        let count = imported.len();
        for rule in &imported {
            self.add_rule(rule.clone());
        }
        info!(count = count, "Imported YARA rules from YAML");
        Ok(imported)
    }

    fn parse_yaml_rule(doc: &yaml_rust2::Yaml) -> Option<YaraRule> {
        let name = doc["name"].as_str()?.to_string();
        let id = doc["id"]
            .as_str()
            .unwrap_or(&uuid::Uuid::new_v4().to_string())
            .to_string();
        let description = doc["description"].as_str().unwrap_or("").to_string();
        let author = doc["author"].as_str().unwrap_or("unknown").to_string();
        let date = doc["date"].as_str().unwrap_or("").to_string();
        let condition = doc["condition"].as_str().unwrap_or("false").to_string();
        let severity = match doc["severity"].as_str().unwrap_or("medium") {
            "critical" => EventSeverity::Critical,
            "high" => EventSeverity::High,
            "medium" => EventSeverity::Medium,
            "low" => EventSeverity::Low,
            _ => EventSeverity::Informational,
        };

        let tags = doc["tags"]
            .as_vec()
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let mut strings = Vec::new();
        if let Some(strs) = doc["strings"].as_vec() {
            for s in strs {
                if let Some(map) = s.as_hash() {
                    for (key, val) in map {
                        let identifier = key.as_str().unwrap_or("unknown").to_string();
                        let value = val.as_str().unwrap_or("").to_string();
                        let string_type = if value.starts_with('/') && value.ends_with('/') {
                            YaraStringType::Regex
                        } else if value
                            .replace(' ', "")
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() || c == '?')
                        {
                            YaraStringType::Hex
                        } else {
                            YaraStringType::Text
                        };
                        strings.push(YaraString {
                            identifier,
                            value: value.trim_matches('/').to_string(),
                            string_type,
                            modifiers: vec![],
                        });
                    }
                }
            }
        }

        Some(YaraRule {
            id,
            name,
            description,
            severity,
            author,
            date,
            tags,
            strings,
            condition,
            enabled: true,
        })
    }

    pub fn export_rules_to_yaml(&self) -> String {
        let mut yaml = String::new();
        for rule in &self.rules {
            yaml.push_str(&format!("name: {}\n", rule.name));
            yaml.push_str(&format!("id: {}\n", rule.id));
            yaml.push_str(&format!("description: \"{}\"\n", rule.description));
            yaml.push_str(&format!("author: \"{}\"\n", rule.author));
            yaml.push_str(&format!("date: \"{}\"\n", rule.date));
            yaml.push_str(&format!(
                "severity: {}\n",
                format!("{:?}", rule.severity).to_lowercase()
            ));
            if !rule.tags.is_empty() {
                yaml.push_str("tags:\n");
                for tag in &rule.tags {
                    yaml.push_str(&format!("  - {}\n", tag));
                }
            }
            if !rule.strings.is_empty() {
                yaml.push_str("strings:\n");
                for s in &rule.strings {
                    yaml.push_str(&format!("  - {}: \"{}\"\n", s.identifier, s.value));
                }
            }
            yaml.push_str(&format!("condition: \"{}\"\n", rule.condition));
            yaml.push_str("---\n");
        }
        yaml
    }

    pub fn toggle_rule(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            info!(rule_id = %rule_id, enabled = enabled, "Toggled YARA rule");
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_engine_new() {
        let engine = YaraEngine::new();
        assert!(engine.rules.is_empty());
        assert!(engine.compiled_rules.is_empty());
        assert_eq!(engine.stats.total_rules, 0);
    }

    #[test]
    fn test_add_and_compile_rule() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "test-001".into(),
            name: "Test Rule".into(),
            description: "A test rule".into(),
            severity: EventSeverity::High,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec!["test".into()],
            strings: vec![YaraString {
                identifier: "$s1".into(),
                value: "hello".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$s1".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        assert_eq!(engine.rules.len(), 1);
        assert!(engine.compiled_rules.contains_key("test-001"));
        assert_eq!(engine.stats.total_rules, 1);
        assert_eq!(engine.stats.compiled_rules, 1);
    }

    #[test]
    fn test_remove_rule() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "rm-001".into(),
            name: "Remove Me".into(),
            description: "test".into(),
            severity: EventSeverity::Low,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![],
            condition: "false".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        assert!(engine.remove_rule("rm-001"));
        assert!(engine.rules.is_empty());
        assert!(!engine.compiled_rules.contains_key("rm-001"));
        assert_eq!(engine.stats.total_rules, 0);
    }

    #[test]
    fn test_remove_nonexistent_rule() {
        let mut engine = YaraEngine::new();
        assert!(!engine.remove_rule("nonexistent"));
    }

    #[test]
    fn test_scan_data_text_match() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "scan-001".into(),
            name: "Scan Test".into(),
            description: "test".into(),
            severity: EventSeverity::High,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$pat".into(),
                value: "malware".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$pat".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let matches = engine.scan_data(b"This file contains malware code");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "Scan Test");
        assert_eq!(matches[0].matched_string, "$pat");
    }

    #[test]
    fn test_scan_data_no_match() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "scan-002".into(),
            name: "No Match".into(),
            description: "test".into(),
            severity: EventSeverity::Low,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$pat".into(),
                value: "malware".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$pat".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let matches = engine.scan_data(b"This file is completely clean");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_disabled_rule() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "disabled-001".into(),
            name: "Disabled".into(),
            description: "test".into(),
            severity: EventSeverity::Low,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$pat".into(),
                value: "test".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$pat".into(),
            enabled: false,
        };
        engine.add_rule(rule);
        let matches = engine.scan_data(b"This contains test data");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_text_convenience() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "text-001".into(),
            name: "Text Scan".into(),
            description: "test".into(),
            severity: EventSeverity::Medium,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$t".into(),
                value: "suspicious".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$t".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let matches = engine.scan_text("This is suspicious behavior");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_regex_match() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "regex-001".into(),
            name: "Regex Scan".into(),
            description: "test".into(),
            severity: EventSeverity::Medium,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$re".into(),
                value: r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}".into(),
                string_type: YaraStringType::Regex,
                modifiers: vec![],
            }],
            condition: "$re".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let matches = engine.scan_text("Connecting to 192.168.1.1 now");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_string, "$re");
    }

    #[test]
    fn test_scan_hex_match() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "hex-001".into(),
            name: "Hex Scan".into(),
            description: "test".into(),
            severity: EventSeverity::High,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$hx".into(),
                value: "deadbeef".into(),
                string_type: YaraStringType::Hex,
                modifiers: vec![],
            }],
            condition: "$hx".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let data = hex::decode("deadbeef01020304").unwrap();
        let matches = engine.scan_data(&data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_nocase_modifier() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "nocase-001".into(),
            name: "Nocase Test".into(),
            description: "test".into(),
            severity: EventSeverity::Low,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$nc".into(),
                value: "suspicious".into(),
                string_type: YaraStringType::Text,
                modifiers: vec!["nocase".into()],
            }],
            condition: "$nc".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let matches = engine.scan_text("This is SUSPICIOUS behavior");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_stats_update() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "stats-001".into(),
            name: "Stats Test".into(),
            description: "test".into(),
            severity: EventSeverity::Low,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![YaraString {
                identifier: "$s".into(),
                value: "match".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$s".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        engine.scan_data(b"match here");
        let stats = engine.get_stats();
        assert_eq!(stats.matches, 1);
        assert_eq!(stats.total_rules, 1);
    }

    #[test]
    fn test_load_default_rules() {
        let mut engine = YaraEngine::new();
        engine.load_default_rules();
        assert!(engine.rules.len() >= 40, "Expected at least 40 built-in rules, got {}", engine.rules.len());
        assert_eq!(engine.compiled_rules.len(), engine.rules.len());
        assert_eq!(engine.stats.total_rules, engine.rules.len());
    }

    #[test]
    fn test_toggle_rule() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "toggle-001".into(),
            name: "Toggle".into(),
            description: "test".into(),
            severity: EventSeverity::Low,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec![],
            strings: vec![],
            condition: "false".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        assert!(engine.toggle_rule("toggle-001", false));
        assert!(!engine.rules[0].enabled);
        assert!(engine.toggle_rule("toggle-001", true));
        assert!(engine.rules[0].enabled);
    }

    #[test]
    fn test_toggle_nonexistent_rule() {
        let mut engine = YaraEngine::new();
        assert!(!engine.toggle_rule("nope", true));
    }

    #[test]
    fn test_list_rules() {
        let mut engine = YaraEngine::new();
        engine.load_default_rules();
        let rules = engine.list_rules();
        assert!(rules.len() >= 40, "Expected at least 40 built-in rules, got {}", rules.len());
    }

    #[test]
    fn test_export_rules_to_yaml() {
        let mut engine = YaraEngine::new();
        let rule = YaraRule {
            id: "exp-001".into(),
            name: "Export Test".into(),
            description: "Test export".into(),
            severity: EventSeverity::Medium,
            author: "tester".into(),
            date: "2024-01-01".into(),
            tags: vec!["test".into()],
            strings: vec![YaraString {
                identifier: "$e".into(),
                value: "export".into(),
                string_type: YaraStringType::Text,
                modifiers: vec![],
            }],
            condition: "$e".into(),
            enabled: true,
        };
        engine.add_rule(rule);
        let yaml = engine.export_rules_to_yaml();
        assert!(yaml.contains("name: Export Test"));
        assert!(yaml.contains("id: exp-001"));
        assert!(yaml.contains("severity: medium"));
    }

    #[test]
    fn test_import_rules_from_yaml() {
        let mut engine = YaraEngine::new();
        let yaml = r#"name: Imported Rule
id: import-001
description: An imported rule
author: tester
date: "2024-01-01"
severity: high
tags:
  - import
  - test
strings:
  - $imp: "imported_string"
condition: "$imp"
"#;
        let result = engine.import_rules_from_yaml(yaml);
        assert!(result.is_ok());
        let imported = result.unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "Imported Rule");
        assert_eq!(imported[0].id, "import-001");
    }
}
