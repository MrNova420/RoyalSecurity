pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DlpError {
    #[error("DLP policy violation: {0}")]
    PolicyViolation(String),
    #[error("Classification failed: {0}")]
    ClassificationFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DlpAction {
    Block,
    Alert,
    Log,
    Quarantine,
    Encrypt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DlpCondition {
    FileSizeExceeds(u64),
    ClassificationAbove(DataClassification),
    ContainsKeyword(String),
    ExternalDestination,
    HighVolumeTransfer,
    PersonalDataPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPolicy {
    pub id: String,
    pub name: String,
    pub data_class: DataClassification,
    pub conditions: Vec<DlpCondition>,
    pub action: DlpAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpViolation {
    pub policy_id: String,
    pub policy_name: String,
    pub user: String,
    pub resource: String,
    pub action_taken: DlpAction,
    pub classification: DataClassification,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccess {
    pub path: String,
    pub user: String,
    pub action: String,
    pub classification: DataClassification,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTransfer {
    pub dst_ip: String,
    pub bytes_out: u64,
    pub user: String,
    pub timestamp: DateTime<Utc>,
}

pub struct DlpEngine {
    policies: Vec<DlpPolicy>,
    violations: Vec<DlpViolation>,
    file_access_log: Vec<FileAccess>,
    transfer_log: Vec<NetworkTransfer>,
    classification_cache: HashMap<String, DataClassification>,
}

impl DlpEngine {
    pub fn new() -> Self {
        info!("Initializing DLP (Data Loss Prevention) engine");
        Self {
            policies: Vec::new(),
            violations: Vec::new(),
            file_access_log: Vec::new(),
            transfer_log: Vec::new(),
            classification_cache: HashMap::new(),
        }
    }

    pub fn check_file_access(&mut self, path: &str, user: &str, action: &str) -> Vec<DlpViolation> {
        let mut violations = Vec::new();

        let classification = self.classification_cache
            .get(path)
            .copied()
            .unwrap_or(DataClassification::Internal);

        let access = FileAccess {
            path: path.to_string(),
            user: user.to_string(),
            action: action.to_string(),
            classification,
            timestamp: Utc::now(),
        };
        self.file_access_log.push(access);

        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            let mut triggered = false;

            for condition in &policy.conditions {
                match condition {
                    DlpCondition::ClassificationAbove(threshold) => {
                        if classification as u32 > *threshold as u32 {
                            triggered = true;
                        }
                    }
                    DlpCondition::ContainsKeyword(ref keyword) => {
                        if path.to_lowercase().contains(&keyword.to_lowercase()) {
                            triggered = true;
                        }
                    }
                    _ => {}
                }
            }

            if triggered {
                let severity = match classification {
                    DataClassification::TopSecret | DataClassification::Restricted => EventSeverity::Critical,
                    DataClassification::Confidential => EventSeverity::High,
                    _ => EventSeverity::Medium,
                };

                let violation = DlpViolation {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    user: user.to_string(),
                    resource: path.to_string(),
                    action_taken: policy.action,
                    classification,
                    message: format!(
                        "File access '{}' by user '{}' violates policy '{}' (classification: {:?})",
                        path, user, policy.name, classification
                    ),
                    severity,
                    timestamp: Utc::now(),
                };

                warn!(
                    path = %path,
                    user = %user,
                    policy = %policy.name,
                    "DLP violation detected"
                );

                violations.push(violation.clone());
                self.violations.push(violation);
            }
        }

        violations
    }

    pub fn classify_data(&mut self, content: &[u8]) -> DataClassification {
        let content_str = String::from_utf8_lossy(content).to_lowercase();

        if content_str.contains("top secret") || content_str.contains("ts//sci") {
            return DataClassification::TopSecret;
        }

        if content_str.contains("confidential") || content_str.contains("proprietary") {
            return DataClassification::Confidential;
        }

        if content_str.contains("restricted") || content_str.contains("internal only") {
            return DataClassification::Restricted;
        }

        if content_str.contains("ssn") || content_str.contains("social security")
            || content_str.contains("credit card") || content_str.contains("password")
        {
            return DataClassification::Confidential;
        }

        if content_str.contains("public") || content_str.contains("press release") {
            return DataClassification::Public;
        }

        if content.len() > 10000 {
            return DataClassification::Internal;
        }

        DataClassification::Internal
    }

    pub fn classify_and_cache(&mut self, path: &str, content: &[u8]) -> DataClassification {
        let classification = self.classify_data(content);
        self.classification_cache.insert(path.to_string(), classification);
        classification
    }

    pub fn check_network_transfer(&mut self, dst_ip: &str, bytes_out: u64, user: &str) -> Vec<DlpViolation> {
        let mut violations = Vec::new();

        let transfer = NetworkTransfer {
            dst_ip: dst_ip.to_string(),
            bytes_out,
            user: user.to_string(),
            timestamp: Utc::now(),
        };
        self.transfer_log.push(transfer);

        let recent_transfers: u64 = self.transfer_log
            .iter()
            .filter(|t| t.user == user)
            .map(|t| t.bytes_out)
            .sum();

        for policy in &self.policies {
            if !policy.enabled {
                continue;
            }

            for condition in &policy.conditions {
                match condition {
                    DlpCondition::ExternalDestination => {
                        if !dst_ip.starts_with("10.") && !dst_ip.starts_with("192.168.")
                            && !dst_ip.starts_with("172.")
                        {
                            let violation = DlpViolation {
                                policy_id: policy.id.clone(),
                                policy_name: policy.name.clone(),
                                user: user.to_string(),
                                resource: format!("Network transfer to {}", dst_ip),
                                action_taken: policy.action,
                                classification: DataClassification::Internal,
                                message: format!(
                                    "External network transfer to '{}' by '{}' ({} bytes) violates policy '{}'",
                                    dst_ip, user, bytes_out, policy.name
                                ),
                                severity: EventSeverity::High,
                                timestamp: Utc::now(),
                            };
                            warn!(dst_ip = %dst_ip, user = %user, "DLP: external transfer detected");
                            violations.push(violation.clone());
                            self.violations.push(violation);
                        }
                    }
                    DlpCondition::HighVolumeTransfer => {
                        if recent_transfers > 100 * 1024 * 1024 {
                            let violation = DlpViolation {
                                policy_id: policy.id.clone(),
                                policy_name: policy.name.clone(),
                                user: user.to_string(),
                                resource: format!("High volume transfer from {}", user),
                                action_taken: policy.action,
                                classification: DataClassification::Internal,
                                message: format!(
                                    "High volume transfer by '{}' ({} bytes total) violates policy '{}'",
                                    user, recent_transfers, policy.name
                                ),
                                severity: EventSeverity::High,
                                timestamp: Utc::now(),
                            };
                            warn!(user = %user, bytes = recent_transfers, "DLP: high volume transfer");
                            violations.push(violation.clone());
                            self.violations.push(violation);
                        }
                    }
                    _ => {}
                }
            }
        }

        violations
    }

    pub fn add_policy(&mut self, policy: DlpPolicy) {
        info!(id = %policy.id, name = %policy.name, "Adding DLP policy");
        self.policies.push(policy);
    }

    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    pub fn get_violations(&self) -> &[DlpViolation] {
        &self.violations
    }

    pub fn get_policies(&self) -> &[DlpPolicy] {
        &self.policies
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(id: &str, name: &str, data_class: DataClassification, action: DlpAction) -> DlpPolicy {
        DlpPolicy {
            id: id.to_string(),
            name: name.to_string(),
            data_class,
            conditions: vec![DlpCondition::ClassificationAbove(DataClassification::Public)],
            action,
            enabled: true,
        }
    }

    #[test]
    fn test_dlp_engine_new() {
        let engine = DlpEngine::new();
        assert!(engine.violation_count() == 0);
        assert!(engine.get_policies().is_empty());
    }

    #[test]
    fn test_classify_data_restricted() {
        let mut engine = DlpEngine::new();
        let classification = engine.classify_data(b"This document is Restricted internal only");
        assert_eq!(classification, DataClassification::Restricted);
    }

    #[test]
    fn test_classify_data_confidential() {
        let mut engine = DlpEngine::new();
        let classification = engine.classify_data(b"This contains SSN and credit card numbers");
        assert_eq!(classification, DataClassification::Confidential);
    }

    #[test]
    fn test_classify_data_top_secret() {
        let mut engine = DlpEngine::new();
        let classification = engine.classify_data(b"TOP SECRET // SCI");
        assert_eq!(classification, DataClassification::TopSecret);
    }

    #[test]
    fn test_check_file_access_no_policy() {
        let mut engine = DlpEngine::new();
        let violations = engine.check_file_access("/secret/doc.txt", "user1", "read");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_check_file_access_violation() {
        let mut engine = DlpEngine::new();
        engine.add_policy(make_policy("p1", "Confidential Policy", DataClassification::Confidential, DlpAction::Block));
        engine.classify_and_cache("/secret/doc.txt", b"This is Confidential proprietary data");
        let violations = engine.check_file_access("/secret/doc.txt", "user1", "read");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].action_taken, DlpAction::Block);
    }

    #[test]
    fn test_check_network_transfer_external() {
        let mut engine = DlpEngine::new();
        let mut policy = make_policy("p2", "External Transfer", DataClassification::Public, DlpAction::Alert);
        policy.conditions = vec![DlpCondition::ExternalDestination];
        engine.add_policy(policy);
        let violations = engine.check_network_transfer("8.8.8.8", 5000, "user1");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_add_policy() {
        let mut engine = DlpEngine::new();
        engine.add_policy(make_policy("p3", "Test Policy", DataClassification::Internal, DlpAction::Log));
        assert_eq!(engine.get_policies().len(), 1);
    }

    #[test]
    fn test_violation_count() {
        let mut engine = DlpEngine::new();
        engine.add_policy(make_policy("p4", "Test", DataClassification::Public, DlpAction::Alert));
        engine.classify_and_cache("/doc.txt", b"some content");
        engine.check_file_access("/doc.txt", "u1", "read");
        assert_eq!(engine.violation_count(), 1);
    }

    #[test]
    fn test_classify_and_cache() {
        let mut engine = DlpEngine::new();
        let c = engine.classify_and_cache("/test.txt", b"Restricted data here");
        assert_eq!(c, DataClassification::Restricted);
    }
}
