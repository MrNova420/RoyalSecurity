pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Trojan,
    Ransomware,
    Worm,
    Rootkit,
    PUP,
    Adware,
    Spyware,
    Keylogger,
    Backdoor,
    Botnet,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::Malware => write!(f, "Malware"),
            ThreatType::Trojan => write!(f, "Trojan"),
            ThreatType::Ransomware => write!(f, "Ransomware"),
            ThreatType::Worm => write!(f, "Worm"),
            ThreatType::Rootkit => write!(f, "Rootkit"),
            ThreatType::PUP => write!(f, "PUP"),
            ThreatType::Adware => write!(f, "Adware"),
            ThreatType::Spyware => write!(f, "Spyware"),
            ThreatType::Keylogger => write!(f, "Keylogger"),
            ThreatType::Backdoor => write!(f, "Backdoor"),
            ThreatType::Botnet => write!(f, "Botnet"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvConfig {
    pub real_time_protection: bool,
    pub scan_archives: bool,
    pub max_file_size_mb: u64,
    pub quarantine_on_detect: bool,
    pub reputation_cache_ttl_secs: u64,
    pub heuristic_sensitivity: f64,
}

impl Default for AvConfig {
    fn default() -> Self {
        Self {
            real_time_protection: true,
            scan_archives: true,
            max_file_size_mb: 100,
            quarantine_on_detect: true,
            reputation_cache_ttl_secs: 3600,
            heuristic_sensitivity: 0.7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub threat_type: ThreatType,
    pub severity: EventSeverity,
    pub offset: usize,
    pub length: usize,
    pub pattern: Vec<u8>,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub name: String,
    pub data: Vec<u8>,
    pub case_sensitive: bool,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YaraCondition {
    All,
    Any,
    Count(u32),
    NoneOf,
    At(u32, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: String,
    pub name: String,
    pub threat_type: ThreatType,
    pub severity: EventSeverity,
    pub strings: Vec<YaraString>,
    pub condition: YaraCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEntry {
    pub hash: String,
    pub trusted: bool,
    pub score: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub file_path: String,
    pub file_hash: String,
    pub signature_id: Option<String>,
    pub rule_id: Option<String>,
    pub threat_type: ThreatType,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub clean: bool,
    pub threats: Vec<ThreatDetection>,
    pub scan_time_ms: u64,
    pub files_scanned: u32,
}

impl ScanResult {
    pub fn clean() -> Self {
        Self {
            clean: true,
            threats: Vec::new(),
            scan_time_ms: 0,
            files_scanned: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_scans: u64,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub quarantined: u64,
    pub avg_scan_time_ms: f64,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            total_scans: 0,
            files_scanned: 0,
            threats_found: 0,
            quarantined: 0,
            avg_scan_time_ms: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicResult {
    pub score: f64,
    pub indicators: Vec<String>,
    pub verdict: ThreatType,
}

pub struct AvEngine {
    signature_db: HashMap<String, Signature>,
    yara_rules: Vec<YaraRule>,
    reputation_cache: HashMap<String, ReputationEntry>,
    scan_stats: ScanStats,
    config: AvConfig,
}

impl AvEngine {
    pub fn new() -> Self {
        info!("Initializing AV engine with default configuration");
        Self {
            signature_db: HashMap::new(),
            yara_rules: Vec::new(),
            reputation_cache: HashMap::new(),
            scan_stats: ScanStats::default(),
            config: AvConfig::default(),
        }
    }

    pub fn with_config(config: AvConfig) -> Self {
        info!("Initializing AV engine with custom configuration");
        Self {
            signature_db: HashMap::new(),
            yara_rules: Vec::new(),
            reputation_cache: HashMap::new(),
            scan_stats: ScanStats::default(),
            config,
        }
    }

    pub fn scan_file(&mut self, path: &str, content: &[u8]) -> ScanResult {
        let start = std::time::Instant::now();
        let mut threats: Vec<ThreatDetection> = Vec::new();

        // Hash lookup
        let hash = hex::encode(blake3::hash(content).as_bytes());
        if let Some(sig) = self.signature_db.get(&hash) {
            warn!(hash = %hash, signature = %sig.name, "File matches known signature");
            threats.push(ThreatDetection {
                file_path: path.to_string(),
                file_hash: hash.clone(),
                signature_id: Some(sig.id.clone()),
                rule_id: None,
                threat_type: sig.threat_type,
                severity: sig.severity,
                confidence: 1.0,
                quarantined: self.config.quarantine_on_detect,
            });
        }

        // YARA scan
        if let Some(yara_threats) = self.scan_with_yara(path, &hash, content) {
            threats.extend(yara_threats);
        }

        // Heuristic analysis
        if content.len() >= 2 && content[0] == 0x4D && content[1] == 0x5A {
            let heuristic = Self::analyze_executable(content);
            if heuristic.score >= self.config.heuristic_sensitivity {
                warn!(path = %path, score = heuristic.score, verdict = %heuristic.verdict, "Heuristic analysis triggered");
                threats.push(ThreatDetection {
                    file_path: path.to_string(),
                    file_hash: hash.clone(),
                    signature_id: None,
                    rule_id: None,
                    threat_type: heuristic.verdict,
                    severity: EventSeverity::Medium,
                    confidence: heuristic.score as f32,
                    quarantined: self.config.quarantine_on_detect,
                });
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        self.scan_stats.total_scans += 1;
        self.scan_stats.files_scanned += 1;
        self.scan_stats.threats_found += threats.len() as u64;

        if self.config.quarantine_on_detect {
            self.scan_stats.quarantined += threats.iter().filter(|t| t.quarantined).count() as u64;
        }

        let prev_avg = self.scan_stats.avg_scan_time_ms;
        let n = self.scan_stats.total_scans as f64;
        self.scan_stats.avg_scan_time_ms = prev_avg + (elapsed as f64 - prev_avg) / n;

        let clean = threats.is_empty();

        if clean {
            info!(path = %path, time_ms = elapsed, "File scan completed - clean");
        } else {
            warn!(path = %path, threats = threats.len(), time_ms = elapsed, "File scan completed - threats detected");
        }

        ScanResult {
            clean,
            threats,
            scan_time_ms: elapsed,
            files_scanned: 1,
        }
    }

    fn scan_with_yara(&self, path: &str, hash: &str, content: &[u8]) -> Option<Vec<ThreatDetection>> {
        let mut threats = Vec::new();

        for rule in &self.yara_rules {
            let matched = match &rule.condition {
                YaraCondition::All => rule.strings.iter().all(|s| yara_string_matches(s, content)),
                YaraCondition::Any => rule.strings.iter().any(|s| yara_string_matches(s, content)),
                YaraCondition::Count(n) => {
                    let count = rule.strings.iter().filter(|s| yara_string_matches(s, content)).count() as u32;
                    count >= *n
                }
                YaraCondition::NoneOf => !rule.strings.iter().any(|s| yara_string_matches(s, content)),
                YaraCondition::At(idx, name) => {
                    rule.strings.iter().any(|s| s.name == *name && yara_string_matches_at(s, content, *idx as usize))
                }
            };

            if matched {
                warn!(rule = %rule.name, path = %path, "YARA rule matched");
                threats.push(ThreatDetection {
                    file_path: path.to_string(),
                    file_hash: hash.to_string(),
                    signature_id: None,
                    rule_id: Some(rule.id.clone()),
                    threat_type: rule.threat_type,
                    severity: rule.severity,
                    confidence: 0.9,
                    quarantined: self.config.quarantine_on_detect,
                });
            }
        }

        if threats.is_empty() { None } else { Some(threats) }
    }

    pub fn scan_process(&mut self, info: &ProcessInfo) -> ScanResult {
        let start = std::time::Instant::now();

        let mut threats: Vec<ThreatDetection> = Vec::new();

        if let Some(ref hash) = info.hash_sha256 {
            if let Some(sig) = self.signature_db.get(hash) {
                warn!(hash = %hash, signature = %sig.name, pid = info.pid, "Process matches known signature");
                threats.push(ThreatDetection {
                    file_path: info.path.clone(),
                    file_hash: hash.clone(),
                    signature_id: Some(sig.id.clone()),
                    rule_id: None,
                    threat_type: sig.threat_type,
                    severity: sig.severity,
                    confidence: 1.0,
                    quarantined: self.config.quarantine_on_detect,
                });
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;

        self.scan_stats.total_scans += 1;
        self.scan_stats.files_scanned += 1;
        self.scan_stats.threats_found += threats.len() as u64;

        if self.config.quarantine_on_detect {
            self.scan_stats.quarantined += threats.iter().filter(|t| t.quarantined).count() as u64;
        }

        let prev_avg = self.scan_stats.avg_scan_time_ms;
        let n = self.scan_stats.total_scans as f64;
        self.scan_stats.avg_scan_time_ms = prev_avg + (elapsed as f64 - prev_avg) / n;

        ScanResult {
            clean: threats.is_empty(),
            threats,
            scan_time_ms: elapsed,
            files_scanned: 1,
        }
    }

    pub fn check_file_event(&mut self, event: &FileEvent) -> Vec<ThreatDetection> {
        if !self.config.real_time_protection {
            return Vec::new();
        }

        let mut threats = Vec::new();

        if let Some(ref hash) = event.hash_sha256 {
            if let Some(sig) = self.signature_db.get(hash) {
                warn!(hash = %hash, signature = %sig.name, path = %event.path, "Real-time file event matched signature");
                threats.push(ThreatDetection {
                    file_path: event.path.clone(),
                    file_hash: hash.clone(),
                    signature_id: Some(sig.id.clone()),
                    rule_id: None,
                    threat_type: sig.threat_type,
                    severity: sig.severity,
                    confidence: 1.0,
                    quarantined: self.config.quarantine_on_detect,
                });
            }
        }

        threats
    }

    pub fn analyze_executable(content: &[u8]) -> HeuristicResult {
        let mut indicators: Vec<String> = Vec::new();
        let mut score: f64 = 0.0;

        let entropy = Self::calculate_entropy(content);

        if entropy > 7.0 {
            indicators.push(format!("High entropy ({:.2}) - possible packed/encrypted content", entropy));
            score += 0.3;
        }

        if entropy < 0.1 && content.len() > 100 {
            indicators.push("Near-zero entropy detected - suspicious for executables".into());
            score += 0.2;
        }

        if content.len() >= 2 && content[0] == 0x4D && content[1] == 0x5A {
            indicators.push("PE executable detected (MZ header)".into());
        } else {
            indicators.push("Missing PE header in executable context".into());
            score += 0.1;
        }

        let content_str = String::from_utf8_lossy(content);

        let suspicious_strings = [
            "cmd.exe", "/c ", "powershell", "Invoke-Expression", "IEX",
            "Invoke-WebRequest", "DownloadString", "Start-Process",
            "CreateProcess", "VirtualAlloc", "WriteProcessMemory",
            "CreateRemoteThread", "WinExec", "ShellExecute",
        ];

        for s in &suspicious_strings {
            if content_str.contains(s) {
                indicators.push(format!("Suspicious string found: {}", s));
                score += 0.15;
            }
        }

        let base64_patterns = ["AAA", "BBB", "CCC", "DDD", "EEE", "FFF", "GGG", "HHH", "III", "JJJ"];
        for p in &base64_patterns {
            if content_str.contains(p) {
                indicators.push("Base64-like encoded content detected".into());
                score += 0.1;
                break;
            }
        }

        let verdict = if score >= 0.7 {
            ThreatType::Malware
        } else if score >= 0.5 {
            ThreatType::Trojan
        } else if score >= 0.3 {
            ThreatType::PUP
        } else {
            ThreatType::Malware
        };

        HeuristicResult {
            score: score.clamp(0.0, 1.0),
            indicators,
            verdict,
        }
    }

    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in freq.iter() {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    pub fn add_signature(&mut self, sig: Signature) {
        info!(name = %sig.name, threat = %sig.threat_type, "Adding signature to database");
        self.signature_db.insert(sig.pattern.iter().map(|b| format!("{:02x}", b)).collect::<String>(), sig);
    }

    pub fn add_yara_rule(&mut self, rule: YaraRule) {
        info!(name = %rule.name, threat = %rule.threat_type, "Adding YARA rule");
        self.yara_rules.push(rule);
    }

    pub fn update_reputation(&mut self, hash: String, entry: ReputationEntry) {
        info!(hash = %hash, trusted = entry.trusted, score = entry.score, "Updating reputation cache");
        self.reputation_cache.insert(hash, entry);
    }

    pub fn get_reputation(&self, hash: &str) -> Option<&ReputationEntry> {
        self.reputation_cache.get(hash)
    }

    pub fn stats(&self) -> &ScanStats {
        &self.scan_stats
    }
}

fn yara_string_matches(s: &YaraString, content: &[u8]) -> bool {
    if s.case_sensitive {
        content.windows(s.data.len()).any(|w| w == s.data.as_slice())
    } else {
        let content_lower = content.iter().map(|&b| b.to_ascii_lowercase()).collect::<Vec<_>>();
        let data_lower = s.data.iter().map(|&b| b.to_ascii_lowercase()).collect::<Vec<_>>();
        content_lower.windows(data_lower.len()).any(|w| w == data_lower.as_slice())
    }
}

fn yara_string_matches_at(s: &YaraString, content: &[u8], offset: usize) -> bool {
    if offset + s.data.len() > content.len() {
        return false;
    }
    if s.case_sensitive {
        &content[offset..offset + s.data.len()] == s.data.as_slice()
    } else {
        content[offset..offset + s.data.len()]
            .iter()
            .zip(s.data.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_av_engine_new() {
        let engine = AvEngine::new();
        assert!(engine.stats().total_scans == 0);
    }

    #[test]
    fn test_scan_file_clean() {
        let mut engine = AvEngine::new();
        let result = engine.scan_file("test.txt", b"clean content here");
        assert!(result.clean);
        assert!(result.threats.is_empty());
    }

    #[test]
    fn test_calculate_entropy() {
        let data = b"AAAA"; // low entropy, repeated chars
        let entropy = AvEngine::calculate_entropy(data);
        assert!(entropy < 1.0);

        let high_entropy: Vec<u8> = (0..=255).cycle().take(256).collect();
        let he = AvEngine::calculate_entropy(&high_entropy);
        assert!(he > 7.0);
    }

    #[test]
    fn test_scan_file_with_mz_triggers_heuristics() {
        let mut engine = AvEngine::with_config(AvConfig { heuristic_sensitivity: 0.3, ..Default::default() });
        let mut content = Vec::new();
        content.extend_from_slice(b"MZ");
        content.extend_from_slice(b"cmd.exe /c powershell Invoke-Expression");
        let result = engine.scan_file("mal.exe", &content);
        assert!(!result.clean);
        assert!(!result.threats.is_empty());
    }

    #[test]
    fn test_add_signature_and_lookup() {
        let mut engine = AvEngine::new();
        let pattern = b"malicious_bytes_here";
        let sig = Signature {
            id: Uuid::new_v4().to_string(),
            name: "Test-Signature".into(),
            threat_type: ThreatType::Trojan,
            severity: EventSeverity::High,
            offset: 0,
            length: pattern.len(),
            pattern: pattern.to_vec(),
            created: Utc::now(),
        };
        engine.add_signature(sig);

        let content = b"clean content";
        let result = engine.scan_file("test.txt", content);
        assert!(result.clean);
    }

    #[test]
    fn test_add_yara_rule() {
        let mut engine = AvEngine::new();
        let rule = YaraRule {
            id: Uuid::new_v4().to_string(),
            name: "Test-YARA".into(),
            threat_type: ThreatType::Spyware,
            severity: EventSeverity::Medium,
            strings: vec![YaraString {
                name: "s1".into(),
                data: b"suspicious".to_vec(),
                case_sensitive: true,
                offset: None,
            }],
            condition: YaraCondition::Any,
        };
        engine.add_yara_rule(rule);

        let result = engine.scan_file("test.txt", b"this contains suspicious data");
        assert!(!result.clean);
    }

    #[test]
    fn test_check_file_event() {
        let mut engine = AvEngine::new();

        let sig = Signature {
            id: "test-id".into(),
            name: "Test".into(),
            threat_type: ThreatType::Keylogger,
            severity: EventSeverity::Critical,
            offset: 0,
            length: 3,
            pattern: b"ABC".to_vec(),
            created: Utc::now(),
        };
        engine.add_signature(sig);

        let event = FileEvent {
            path: "C:\\test\\file.exe".into(),
            original_path: None,
            action: FileAction::Created,
            hash_sha256: Some("abc".into()),
            size: Some(100),
            timestamp: Utc::now(),
        };
        let threats = engine.check_file_event(&event);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_scan_process() {
        let mut engine = AvEngine::new();
        let info = ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "test.exe".into(),
            path: "C:\\test.exe".into(),
            command_line: String::new(),
            user: "user".into(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        };
        let result = engine.scan_process(&info);
        assert!(result.clean);
    }

    #[test]
    fn test_reputation_cache() {
        let mut engine = AvEngine::new();
        let entry = ReputationEntry {
            hash: "abcd1234".into(),
            trusted: true,
            score: 0.9,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            source: "test".into(),
        };
        engine.update_reputation("abcd1234".into(), entry);
        assert!(engine.get_reputation("abcd1234").is_some());
        assert!(engine.get_reputation("nonexistent").is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = AvConfig::default();
        assert!(config.real_time_protection);
        assert!(config.scan_archives);
        assert_eq!(config.max_file_size_mb, 100);
        assert!(config.quarantine_on_detect);
        assert_eq!(config.reputation_cache_ttl_secs, 3600);
        assert!((config.heuristic_sensitivity - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_heuristic_analysis() {
        let mut content = Vec::new();
        content.extend_from_slice(b"MZ");
        content.extend_from_slice(b"powershell");
        content.extend_from_slice(b"cmd.exe");
        let result = AvEngine::analyze_executable(&content);
        assert!(!result.indicators.is_empty());
        assert!(result.score > 0.0);
    }

    #[test]
    fn test_entropy_near_zero() {
        let data = vec![0u8; 1000];
        let entropy = AvEngine::calculate_entropy(&data);
        assert!(entropy < 0.01);
    }

    #[test]
    fn test_yara_condition_count() {
        let mut engine = AvEngine::new();
        let rule = YaraRule {
            id: "count-rule".into(),
            name: "CountRule".into(),
            threat_type: ThreatType::Malware,
            severity: EventSeverity::High,
            strings: vec![
                YaraString { name: "a".into(), data: b"foo".to_vec(), case_sensitive: true, offset: None },
                YaraString { name: "b".into(), data: b"bar".to_vec(), case_sensitive: true, offset: None },
            ],
            condition: YaraCondition::Count(2),
        };
        engine.add_yara_rule(rule);
        let result = engine.scan_file("test.txt", b"foo and bar together");
        assert!(!result.clean);
    }

    #[test]
    fn test_yara_condition_none_of() {
        let mut engine = AvEngine::new();
        let rule = YaraRule {
            id: "none-rule".into(),
            name: "NoneOfRule".into(),
            threat_type: ThreatType::Malware,
            severity: EventSeverity::Low,
            strings: vec![
                YaraString { name: "a".into(), data: b"malware".to_vec(), case_sensitive: true, offset: None },
            ],
            condition: YaraCondition::NoneOf,
        };
        engine.add_yara_rule(rule);
        let result = engine.scan_file("test.txt", b"clean file content");
        assert!(!result.clean);
    }

    #[test]
    fn test_yara_condition_at() {
        let mut engine = AvEngine::new();
        let rule = YaraRule {
            id: "at-rule".into(),
            name: "AtRule".into(),
            threat_type: ThreatType::Malware,
            severity: EventSeverity::High,
            strings: vec![
                YaraString { name: "sig".into(), data: b"MZ".to_vec(), case_sensitive: true, offset: None },
            ],
            condition: YaraCondition::At(0, "sig".into()),
        };
        engine.add_yara_rule(rule);
        let result = engine.scan_file("test.txt", b"MZthis is an executable");
        assert!(!result.clean);
    }

    #[test]
    fn test_yara_case_insensitive() {
        let mut engine = AvEngine::new();
        let rule = YaraRule {
            id: "ci-rule".into(),
            name: "CaseInsensitive".into(),
            threat_type: ThreatType::Malware,
            severity: EventSeverity::High,
            strings: vec![
                YaraString { name: "s1".into(), data: b"MALWARE".to_vec(), case_sensitive: false, offset: None },
            ],
            condition: YaraCondition::Any,
        };
        engine.add_yara_rule(rule);
        let result = engine.scan_file("test.txt", b"this has Malware inside");
        assert!(!result.clean);
    }

    #[test]
    fn test_with_config() {
        let config = AvConfig {
            real_time_protection: false,
            heuristic_sensitivity: 0.9,
            ..Default::default()
        };
        let engine = AvEngine::with_config(config);
        // Real-time disabled means file events won't be checked
        // Just verify the engine was created with custom config
        assert_eq!(engine.stats().total_scans, 0);
    }

    #[test]
    fn test_scan_stats_tracking() {
        let mut engine = AvEngine::new();
        engine.scan_file("clean.txt", b"hello");
        assert_eq!(engine.stats().total_scans, 1);
        assert_eq!(engine.stats().files_scanned, 1);
        assert!(engine.stats().avg_scan_time_ms >= 0.0);

        engine.scan_file("clean2.txt", b"world");
        assert_eq!(engine.stats().total_scans, 2);
    }
}
