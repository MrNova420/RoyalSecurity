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
        let defaults = vec![
            YaraRule {
                id: "yar-001".into(),
                name: "Ransomware File Extensions".into(),
                description: "Detects common ransomware encrypted file extensions".into(),
                severity: EventSeverity::Critical,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["ransomware".into(), "malware".into()],
                strings: vec![
                    YaraString { identifier: "$ext1".into(), value: ".encrypted".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$ext2".into(), value: ".locked".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$ext3".into(), value: ".crypto".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                ],
                condition: "$ext1 or $ext2 or $ext3".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-002".into(),
                name: "Ransomware Note Keywords".into(),
                description: "Detects common ransomware note text patterns".into(),
                severity: EventSeverity::Critical,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["ransomware".into(), "malware".into()],
                strings: vec![
                    YaraString { identifier: "$note1".into(), value: "Your files have been encrypted".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$note2".into(), value: "decrypt your files".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$note3".into(), value: "bitcoin wallet".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                ],
                condition: "$note1 or ($note2 and $note3)".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-003".into(),
                name: "Mimikatz Credential Dumping".into(),
                description: "Detects Mimikatz credential dumping patterns".into(),
                severity: EventSeverity::Critical,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["credential".into(), "lateral-movement".into(), "mimikatz".into()],
                strings: vec![
                    YaraString { identifier: "$m1".into(), value: "mimikatz".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$m2".into(), value: "sekurlsa::logonpasswords".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$m3".into(), value: "lsadump::sam".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                ],
                condition: "$m1 or $m2 or $m3".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-004".into(),
                name: "Credential File Patterns".into(),
                description: "Detects patterns related to credential theft".into(),
                severity: EventSeverity::High,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["credential".into(), "theft".into()],
                strings: vec![
                    YaraString { identifier: "$c1".into(), value: "SAM".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$c2".into(), value: "SYSTEM".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$c3".into(), value: "ntds.dit".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                ],
                condition: "$c1 and $c2 and $c3".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-005".into(),
                name: "Suspicious PowerShell Commands".into(),
                description: "Detects suspicious PowerShell command patterns".into(),
                severity: EventSeverity::High,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["powershell".into(), "execution".into(), "suspicious".into()],
                strings: vec![
                    YaraString { identifier: "$ps1".into(), value: "Invoke-Expression".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$ps2".into(), value: "IEX".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$ps3".into(), value: "DownloadString".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$ps4".into(), value: "bypass".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                ],
                condition: "$ps1 or $ps2 or ($ps3 and $ps4)".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-006".into(),
                name: "Script Obfuscation Patterns".into(),
                description: "Detects common script obfuscation techniques".into(),
                severity: EventSeverity::High,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["obfuscation".into(), "script".into(), "malware".into()],
                strings: vec![
                    YaraString { identifier: "$o1".into(), value: "eval(".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$o2".into(), value: "fromCharCode".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$o3".into(), value: "Base64".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$o4".into(), value: "charCodeAt".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                ],
                condition: "$o1 and ($o2 or $o3 or $o4)".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-007".into(),
                name: "PsExec Lateral Movement".into(),
                description: "Detects PsExec-based lateral movement".into(),
                severity: EventSeverity::High,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["lateral-movement".into(), "psexec".into(), "remote".into()],
                strings: vec![
                    YaraString { identifier: "$px1".into(), value: "psexec".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$px2".into(), value: "\\\\IPC$".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$px3".into(), value: "PsExec".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                ],
                condition: "$px1 or $px2 or $px3".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-008".into(),
                name: "WMI Lateral Movement".into(),
                description: "Detects WMI-based lateral movement".into(),
                severity: EventSeverity::High,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["lateral-movement".into(), "wmi".into(), "remote".into()],
                strings: vec![
                    YaraString { identifier: "$w1".into(), value: "Win32_Process".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$w2".into(), value: "Create".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$w3".into(), value: "wmic".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                ],
                condition: "($w1 and $w2) or $w3".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-009".into(),
                name: "Reverse Shell Patterns".into(),
                description: "Detects common reverse shell code patterns".into(),
                severity: EventSeverity::Critical,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["shell".into(), "backdoor".into(), "malware".into()],
                strings: vec![
                    YaraString { identifier: "$sh1".into(), value: "cmd.exe /c".into(), string_type: YaraStringType::Text, modifiers: vec!["nocase".into()] },
                    YaraString { identifier: "$sh2".into(), value: "/bin/sh".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$sh3".into(), value: "socket".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                ],
                condition: "$sh1 or $sh2 or $sh3".into(),
                enabled: true,
            },
            YaraRule {
                id: "yar-010".into(),
                name: "Registry Persistence".into(),
                description: "Detects registry-based persistence mechanisms".into(),
                severity: EventSeverity::Medium,
                author: "RoyalSecurity".into(),
                date: "2024-01-01".into(),
                tags: vec!["persistence".into(), "registry".into()],
                strings: vec![
                    YaraString { identifier: "$reg1".into(), value: "CurrentVersion\\Run".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$reg2".into(), value: "CurrentVersion\\RunOnce".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$reg3".into(), value: "Winlogon\\Shell".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                    YaraString { identifier: "$reg4".into(), value: "Winlogon\\Userinit".into(), string_type: YaraStringType::Text, modifiers: vec![] },
                ],
                condition: "$reg1 or $reg2 or $reg3 or $reg4".into(),
                enabled: true,
            },
        ];

        for rule in defaults {
            self.add_rule(rule);
        }
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
        assert_eq!(engine.rules.len(), 10);
        assert_eq!(engine.compiled_rules.len(), 10);
        assert_eq!(engine.stats.total_rules, 10);
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
        assert_eq!(rules.len(), 10);
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
