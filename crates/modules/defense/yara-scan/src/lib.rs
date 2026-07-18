pub mod prelude;

use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanString {
    pub name: String,
    pub data: Vec<u8>,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanRule {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub strings: Vec<YaraScanString>,
    pub condition: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub rule_id: String,
    pub rule_name: String,
    pub matched_strings: Vec<String>,
    pub namespace: String,
    pub tags: Vec<String>,
    pub severity: EventSeverity,
}

pub struct YaraScanner {
    rules: Vec<YaraScanRule>,
}

impl YaraScanner {
    pub fn new() -> Self {
        info!("Initializing YARA Scanner");
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: YaraScanRule) {
        info!(rule_id = %rule.id, name = %rule.name, namespace = %rule.namespace, "Adding YARA rule");
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        let removed = self.rules.len() < before;
        if removed {
            info!(rule_id = rule_id, "Removed YARA rule");
        }
        removed
    }

    pub fn scan_data(&self, data: &[u8]) -> Vec<YaraScanResult> {
        let mut results = Vec::new();

        for rule in &self.rules {
            let mut matched_strings = Vec::new();

            for yara_string in &rule.strings {
                let matched = if yara_string.case_sensitive {
                    data.windows(yara_string.data.len())
                        .any(|window| window == yara_string.data.as_slice())
                } else {
                    let data_lower: Vec<u8> = data.iter().map(|&b| b.to_ascii_lowercase()).collect();
                    let pattern_lower: Vec<u8> = yara_string
                        .data
                        .iter()
                        .map(|&b| b.to_ascii_lowercase())
                        .collect();
                    data_lower
                        .windows(pattern_lower.len())
                        .any(|window| window == pattern_lower.as_slice())
                };

                if matched {
                    matched_strings.push(yara_string.name.clone());
                }
            }

            let condition_met = match rule.condition.as_str() {
                "all" => matched_strings.len() == rule.strings.len(),
                "any" => !matched_strings.is_empty(),
                n if n.starts_with("count(") => {
                    let num_str = n.trim_start_matches("count(").trim_end_matches(')');
                    if let Ok(threshold) = num_str.parse::<usize>() {
                        matched_strings.len() >= threshold
                    } else {
                        false
                    }
                }
                _ => !matched_strings.is_empty(),
            };

            if condition_met && !matched_strings.is_empty() {
                let severity = rule
                    .meta
                    .get("severity")
                    .and_then(|s| match s.as_str() {
                        "critical" => Some(EventSeverity::Critical),
                        "high" => Some(EventSeverity::High),
                        "medium" => Some(EventSeverity::Medium),
                        "low" => Some(EventSeverity::Low),
                        _ => None,
                    })
                    .unwrap_or(EventSeverity::Medium);

                warn!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    matched = ?matched_strings,
                    "YARA rule matched"
                );

                results.push(YaraScanResult {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    matched_strings,
                    namespace: rule.namespace.clone(),
                    tags: rule.tags.clone(),
                    severity,
                });
            }
        }

        results
    }

    pub fn scan_text(&self, text: &str) -> Vec<YaraScanResult> {
        self.scan_data(text.as_bytes())
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn get_rules(&self) -> &[YaraScanRule] {
        &self.rules
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, name: &str, pattern: &[u8], condition: &str) -> YaraScanRule {
        let mut meta = HashMap::new();
        meta.insert("severity".to_string(), "high".to_string());
        YaraScanRule {
            id: id.to_string(),
            name: name.to_string(),
            namespace: "default".to_string(),
            strings: vec![YaraScanString {
                name: "s1".to_string(),
                data: pattern.to_vec(),
                case_sensitive: true,
            }],
            condition: condition.to_string(),
            tags: vec!["malware".to_string()],
            meta,
        }
    }

    #[test]
    fn test_yara_scanner_new() {
        let scanner = YaraScanner::new();
        assert_eq!(scanner.rule_count(), 0);
    }

    #[test]
    fn test_add_and_remove_rule() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(make_rule("r1", "TestRule", b"malicious", "any"));
        assert_eq!(scanner.rule_count(), 1);
        assert!(scanner.remove_rule("r1"));
        assert_eq!(scanner.rule_count(), 0);
        assert!(!scanner.remove_rule("r1"));
    }

    #[test]
    fn test_scan_data_match() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(make_rule("r1", "Suspicious", b"suspicious", "any"));
        let results = scanner.scan_data(b"this contains suspicious data here");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_name, "Suspicious");
        assert!(results[0].matched_strings.contains(&"s1".to_string()));
    }

    #[test]
    fn test_scan_data_no_match() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(make_rule("r1", "Suspicious", b"malware", "any"));
        let results = scanner.scan_data(b"clean file with nothing bad");
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_text() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(make_rule("r1", "TextRule", b"evil", "any"));
        let results = scanner.scan_text("this text contains evil content");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_case_insensitive_scan() {
        let mut scanner = YaraScanner::new();
        let mut rule = make_rule("r1", "CaseRule", b"malware", "any");
        rule.strings[0].case_sensitive = false;
        scanner.add_rule(rule);

        let results = scanner.scan_data(b"Found MALWARE in the file");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_condition_all_requires_all_strings() {
        let mut scanner = YaraScanner::new();
        let rule = YaraScanRule {
            id: "r2".to_string(),
            name: "AllStrings".to_string(),
            namespace: "test".to_string(),
            strings: vec![
                YaraScanString {
                    name: "s1".to_string(),
                    data: b"alpha".to_vec(),
                    case_sensitive: true,
                },
                YaraScanString {
                    name: "s2".to_string(),
                    data: b"beta".to_vec(),
                    case_sensitive: true,
                },
            ],
            condition: "all".to_string(),
            tags: vec![],
            meta: HashMap::new(),
        };
        scanner.add_rule(rule);

        assert_eq!(scanner.scan_data(b"alpha only").len(), 0);
        assert_eq!(scanner.scan_data(b"beta only").len(), 0);
        assert_eq!(scanner.scan_data(b"alpha and beta").len(), 1);
    }

    #[test]
    fn test_severity_from_meta() {
        let mut scanner = YaraScanner::new();
        let mut rule = make_rule("r1", "CritRule", b"critical_threat", "any");
        rule.meta.insert("severity".to_string(), "critical".to_string());
        scanner.add_rule(rule);

        let results = scanner.scan_data(b"found critical_threat data");
        assert_eq!(results[0].severity, EventSeverity::Critical);
    }

    #[test]
    fn test_get_rules() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(make_rule("r1", "Rule1", b"test1", "any"));
        scanner.add_rule(make_rule("r2", "Rule2", b"test2", "any"));
        assert_eq!(scanner.get_rules().len(), 2);
    }

    #[test]
    fn test_condition_count() {
        let mut scanner = YaraScanner::new();
        let rule = YaraScanRule {
            id: "r3".to_string(),
            name: "CountRule".to_string(),
            namespace: "test".to_string(),
            strings: vec![
                YaraScanString {
                    name: "s1".to_string(),
                    data: b"foo".to_vec(),
                    case_sensitive: true,
                },
                YaraScanString {
                    name: "s2".to_string(),
                    data: b"bar".to_vec(),
                    case_sensitive: true,
                },
            ],
            condition: "count(2)".to_string(),
            tags: vec![],
            meta: HashMap::new(),
        };
        scanner.add_rule(rule);

        assert_eq!(scanner.scan_data(b"only foo here").len(), 0);
        assert_eq!(scanner.scan_data(b"foo and bar").len(), 1);
    }
}
