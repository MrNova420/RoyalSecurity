pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    Sigma,
    CustomDsl,
    Yara,
    IoC,
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Sigma => write!(f, "Sigma"),
            RuleType::CustomDsl => write!(f, "Custom DSL"),
            RuleType::Yara => write!(f, "YARA"),
            RuleType::IoC => write!(f, "IoC"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedRule {
    pub id: String,
    pub name: String,
    pub rule_type: RuleType,
    pub content: String,
    pub version: u32,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub severity: EventSeverity,
}

pub struct RuleManager {
    rules: HashMap<String, ManagedRule>,
    import_count: u64,
}

impl RuleManager {
    pub fn new() -> Self {
        info!("Initializing rule manager");
        Self {
            rules: HashMap::new(),
            import_count: 0,
        }
    }

    pub fn add_rule(&mut self, rule: ManagedRule) -> String {
        let id = rule.id.clone();
        info!(
            rule_id = %id,
            name = %rule.name,
            rule_type = %rule.rule_type,
            "Adding detection rule"
        );
        self.rules.insert(id.clone(), rule);
        id
    }

    pub fn remove_rule(&mut self, id: &str) -> bool {
        let removed = self.rules.remove(id).is_some();
        if removed {
            info!(rule_id = id, "Removed detection rule");
        }
        removed
    }

    pub fn toggle_rule(&mut self, id: &str, enabled: bool) {
        if let Some(rule) = self.rules.get_mut(id) {
            rule.enabled = enabled;
            info!(rule_id = id, enabled = enabled, "Toggled rule");
        }
    }

    pub fn import_rules(&mut self, content: &str, rule_type: RuleType) -> usize {
        let mut count = 0;
        let lines: Vec<&str> = content.lines().collect();

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(3, '|').collect();
            if parts.len() >= 2 {
                let rule = ManagedRule {
                    id: Uuid::new_v4().to_string(),
                    name: parts[0].trim().to_string(),
                    rule_type,
                    content: trimmed.to_string(),
                    version: 1,
                    enabled: true,
                    tags: parts
                        .get(2)
                        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_default(),
                    severity: EventSeverity::Medium,
                };
                self.rules.insert(rule.id.clone(), rule);
                count += 1;
            }
        }

        self.import_count += count as u64;
        info!(count = count, rule_type = %rule_type, "Imported rules");
        count
    }

    pub fn export_rules(&self) -> String {
        let mut output = String::new();
        for rule in self.rules.values() {
            output.push_str(&format!(
                "{}|{}|{}|v{}|{}|{}|{}\n",
                rule.id,
                rule.name,
                rule.rule_type,
                rule.version,
                if rule.enabled { "enabled" } else { "disabled" },
                rule.severity,
                rule.tags.join(",")
            ));
        }
        output
    }

    pub fn get_rule(&self, id: &str) -> Option<&ManagedRule> {
        self.rules.get(id)
    }

    pub fn rules_by_tag(&self, tag: &str) -> Vec<&ManagedRule> {
        self.rules
            .values()
            .filter(|r| r.tags.iter().any(|t| t == tag))
            .collect()
    }

    pub fn active_rule_count(&self) -> usize {
        self.rules.values().filter(|r| r.enabled).count()
    }

    pub fn total_rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn import_count(&self) -> u64 {
        self.import_count
    }
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule(id: &str, name: &str, tags: Vec<&str>) -> ManagedRule {
        ManagedRule {
            id: id.to_string(),
            name: name.to_string(),
            rule_type: RuleType::Sigma,
            content: "title: Test Rule".to_string(),
            version: 1,
            enabled: true,
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            severity: EventSeverity::High,
        }
    }

    #[test]
    fn test_rule_manager_new() {
        let manager = RuleManager::new();
        assert_eq!(manager.total_rule_count(), 0);
        assert_eq!(manager.active_rule_count(), 0);
    }

    #[test]
    fn test_add_and_get_rule() {
        let mut manager = RuleManager::new();
        let rule = sample_rule("r1", "Test Rule", vec!["mitre"]);
        let id = manager.add_rule(rule);
        assert_eq!(id, "r1");
        let fetched = manager.get_rule("r1");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "Test Rule");
    }

    #[test]
    fn test_remove_rule() {
        let mut manager = RuleManager::new();
        manager.add_rule(sample_rule("r1", "Rule 1", vec![]));
        assert!(manager.remove_rule("r1"));
        assert!(!manager.remove_rule("r1"));
        assert!(manager.get_rule("r1").is_none());
    }

    #[test]
    fn test_toggle_rule() {
        let mut manager = RuleManager::new();
        manager.add_rule(sample_rule("r1", "Rule 1", vec![]));
        manager.toggle_rule("r1", false);
        assert!(!manager.get_rule("r1").unwrap().enabled);
        manager.toggle_rule("r1", true);
        assert!(manager.get_rule("r1").unwrap().enabled);
    }

    #[test]
    fn test_import_rules() {
        let mut manager = RuleManager::new();
        let content = "Rule A|sigma|tag1,tag2\nRule B|sigma|tag3\n\n# comment";
        let count = manager.import_rules(content, RuleType::Sigma);
        assert_eq!(count, 2);
        assert_eq!(manager.total_rule_count(), 2);
        assert_eq!(manager.import_count(), 2);
    }

    #[test]
    fn test_export_rules() {
        let mut manager = RuleManager::new();
        manager.add_rule(sample_rule("r1", "Rule 1", vec!["tag1"]));
        let exported = manager.export_rules();
        assert!(exported.contains("Rule 1"));
        assert!(exported.contains("r1"));
    }

    #[test]
    fn test_rules_by_tag() {
        let mut manager = RuleManager::new();
        manager.add_rule(sample_rule("r1", "Rule 1", vec!["mitre", "lateral"]));
        manager.add_rule(sample_rule("r2", "Rule 2", vec!["credential"]));
        manager.add_rule(sample_rule("r3", "Rule 3", vec!["mitre"]));
        let tagged = manager.rules_by_tag("mitre");
        assert_eq!(tagged.len(), 2);
        let cred_tagged = manager.rules_by_tag("credential");
        assert_eq!(cred_tagged.len(), 1);
    }

    #[test]
    fn test_active_rule_count() {
        let mut manager = RuleManager::new();
        manager.add_rule(sample_rule("r1", "Rule 1", vec![]));
        manager.add_rule(sample_rule("r2", "Rule 2", vec![]));
        assert_eq!(manager.active_rule_count(), 2);
        manager.toggle_rule("r1", false);
        assert_eq!(manager.active_rule_count(), 1);
    }

    #[test]
    fn test_import_empty_content() {
        let mut manager = RuleManager::new();
        let count = manager.import_rules("", RuleType::Yara);
        assert_eq!(count, 0);
    }
}
