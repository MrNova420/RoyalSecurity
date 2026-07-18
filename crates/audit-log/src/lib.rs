pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub max_entries: usize,
    pub sign_entries: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            sign_entries: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub actor_filter: Option<String>,
    pub action_filter: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            actor_filter: None,
            action_filter: None,
            limit: 100,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainIntegrity {
    pub valid: bool,
    pub total_entries: u64,
    pub broken_at: Option<u64>,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
}

#[derive(Debug)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    last_hash: String,
    config: AuditConfig,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: "0".to_string(),
            config: AuditConfig::default(),
        }
    }

    pub fn with_config(config: AuditConfig) -> Self {
        Self {
            entries: Vec::new(),
            last_hash: "0".to_string(),
            config,
        }
    }

    pub fn append(
        &mut self,
        action: &str,
        actor: &str,
        target: &str,
        details: HashMap<String, serde_json::Value>,
    ) -> Result<AuditEntry> {
        if self.entries.len() >= self.config.max_entries {
            return Err(RsError::Audit(format!(
                "Audit log full: {} entries (max {})",
                self.entries.len(),
                self.config.max_entries
            )));
        }

        let sequence = self.entries.len() as u64;
        let timestamp = Utc::now();
        let details_json =
            serde_json::to_string(&details).map_err(|e| RsError::Audit(e.to_string()))?;

        let hash_input = format!(
            "{}{}{}{}{}{}",
            self.last_hash, action, actor, target, timestamp, details_json
        );
        let mut hasher = Sha3_256::new();
        hasher.update(hash_input.as_bytes());
        let current_hash = format!("{:x}", hasher.finalize());

        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp,
            action: action.to_string(),
            actor: actor.to_string(),
            target: target.to_string(),
            details,
            previous_hash: self.last_hash.clone(),
            current_hash: current_hash.clone(),
            sequence,
        };

        self.last_hash = current_hash;
        self.entries.push(entry.clone());

        tracing::info!(
            sequence,
            action = %entry.action,
            actor = %entry.actor,
            "Audit entry recorded"
        );

        Ok(entry)
    }

    pub fn query(&self, filter: &AuditQuery) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let Some(ref start) = filter.start_time {
                    if e.timestamp < *start {
                        return false;
                    }
                }
                if let Some(ref end) = filter.end_time {
                    if e.timestamp > *end {
                        return false;
                    }
                }
                if let Some(ref actor) = filter.actor_filter {
                    if e.actor != *actor {
                        return false;
                    }
                }
                if let Some(ref action) = filter.action_filter {
                    if e.action != *action {
                        return false;
                    }
                }
                true
            })
            .skip(filter.offset)
            .take(filter.limit)
            .collect()
    }

    pub fn verify_chain(&self) -> ChainIntegrity {
        if self.entries.is_empty() {
            return ChainIntegrity {
                valid: true,
                total_entries: 0,
                broken_at: None,
                expected_hash: None,
                actual_hash: None,
            };
        }

        let mut prev_hash = "0".to_string();

        for entry in &self.entries {
            if entry.previous_hash != prev_hash {
                let details_json = serde_json::to_string(&entry.details)
                    .unwrap_or_default();
                let hash_input = format!(
                    "{}{}{}{}{}{}",
                    entry.previous_hash,
                    entry.action,
                    entry.actor,
                    entry.target,
                    entry.timestamp,
                    details_json
                );
                let mut hasher = Sha3_256::new();
                hasher.update(hash_input.as_bytes());
                let expected = format!("{:x}", hasher.finalize());

                return ChainIntegrity {
                    valid: false,
                    total_entries: self.entries.len() as u64,
                    broken_at: Some(entry.sequence),
                    expected_hash: Some(expected),
                    actual_hash: Some(entry.current_hash.clone()),
                };
            }

            let details_json = serde_json::to_string(&entry.details)
                .unwrap_or_default();
            let hash_input = format!(
                "{}{}{}{}{}{}",
                entry.previous_hash,
                entry.action,
                entry.actor,
                entry.target,
                entry.timestamp,
                details_json
            );
            let mut hasher = Sha3_256::new();
            hasher.update(hash_input.as_bytes());
            let recomputed = format!("{:x}", hasher.finalize());

            if recomputed != entry.current_hash {
                return ChainIntegrity {
                    valid: false,
                    total_entries: self.entries.len() as u64,
                    broken_at: Some(entry.sequence),
                    expected_hash: Some(recomputed),
                    actual_hash: Some(entry.current_hash.clone()),
                };
            }

            prev_hash = entry.current_hash.clone();
        }

        ChainIntegrity {
            valid: true,
            total_entries: self.entries.len() as u64,
            broken_at: None,
            expected_hash: None,
            actual_hash: None,
        }
    }

    pub fn get_entry(&self, sequence: u64) -> Option<&AuditEntry> {
        self.entries.get(sequence as usize)
    }

    pub fn last_entry(&self) -> Option<&AuditEntry> {
        self.entries.last()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn export_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.entries).map_err(|e| RsError::Audit(e.to_string()))
    }

    pub fn import_json(&mut self, json: &str) -> Result<usize> {
        let imported: Vec<AuditEntry> =
            serde_json::from_str(json).map_err(|e| RsError::Audit(e.to_string()))?;
        let count = imported.len();

        for entry in imported {
            if self.entries.len() >= self.config.max_entries {
                return Err(RsError::Audit(format!(
                    "Audit log full during import: {} entries (max {})",
                    self.entries.len(),
                    self.config.max_entries
                )));
            }
            self.last_hash = entry.current_hash.clone();
            self.entries.push(entry);
        }

        tracing::info!(count, "Audit entries imported");
        Ok(count)
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_details() -> HashMap<String, serde_json::Value> {
        let mut d = HashMap::new();
        d.insert("key".into(), serde_json::json!("value"));
        d
    }

    #[test]
    fn test_new_log_is_empty() {
        let log = AuditLog::new();
        assert_eq!(log.entry_count(), 0);
        assert!(log.last_entry().is_none());
        assert_eq!(log.last_hash, "0");
    }

    #[test]
    fn test_append_creates_entry_with_hash() {
        let mut log = AuditLog::new();
        let entry = log
            .append("login", "user1", "system", sample_details())
            .unwrap();

        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.action, "login");
        assert_eq!(entry.actor, "user1");
        assert_eq!(entry.target, "system");
        assert!(!entry.current_hash.is_empty());
        assert_eq!(entry.previous_hash, "0");
    }

    #[test]
    fn test_chain_builds_correctly() {
        let mut log = AuditLog::new();

        let e1 = log.append("a1", "actor1", "t1", sample_details()).unwrap();
        let e2 = log.append("a2", "actor2", "t2", sample_details()).unwrap();
        let e3 = log.append("a3", "actor3", "t3", sample_details()).unwrap();

        assert_eq!(e1.previous_hash, "0");
        assert_eq!(e2.previous_hash, e1.current_hash);
        assert_eq!(e3.previous_hash, e2.current_hash);
        assert_ne!(e1.current_hash, e2.current_hash);
        assert_ne!(e2.current_hash, e3.current_hash);
    }

    #[test]
    fn test_verify_chain_passes_on_valid_log() {
        let mut log = AuditLog::new();
        for i in 0..20 {
            let mut details = sample_details();
            details.insert("idx".into(), serde_json::json!(i));
            log.append(
                &format!("action_{}", i),
                "system",
                "target",
                details,
            )
            .unwrap();
        }

        let result = log.verify_chain();
        assert!(result.valid);
        assert_eq!(result.total_entries, 20);
        assert!(result.broken_at.is_none());
    }

    #[test]
    fn test_verify_chain_on_empty_log() {
        let log = AuditLog::new();
        let result = log.verify_chain();
        assert!(result.valid);
        assert_eq!(result.total_entries, 0);
    }

    #[test]
    fn test_query_filters_by_actor() {
        let mut log = AuditLog::new();
        log.append("action", "alice", "target", sample_details())
            .unwrap();
        log.append("action", "bob", "target", sample_details())
            .unwrap();
        log.append("action", "alice", "target", sample_details())
            .unwrap();

        let filter = AuditQuery {
            actor_filter: Some("alice".into()),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.actor == "alice"));
    }

    #[test]
    fn test_query_filters_by_action() {
        let mut log = AuditLog::new();
        log.append("read", "user", "file1", sample_details())
            .unwrap();
        log.append("write", "user", "file2", sample_details())
            .unwrap();
        log.append("read", "user", "file3", sample_details())
            .unwrap();

        let filter = AuditQuery {
            action_filter: Some("read".into()),
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.action == "read"));
    }

    #[test]
    fn test_query_limit_and_offset() {
        let mut log = AuditLog::new();
        for i in 0..10 {
            log.append(
                &format!("action_{}", i),
                "actor",
                "target",
                sample_details(),
            )
            .unwrap();
        }

        let filter = AuditQuery {
            limit: 3,
            offset: 2,
            ..Default::default()
        };
        let results = log.query(&filter);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].sequence, 2);
        assert_eq!(results[1].sequence, 3);
        assert_eq!(results[2].sequence, 4);
    }

    #[test]
    fn test_import_export_roundtrip() {
        let mut log = AuditLog::new();
        log.append("a1", "actor1", "t1", sample_details())
            .unwrap();
        log.append("a2", "actor2", "t2", sample_details())
            .unwrap();

        let json = log.export_json().unwrap();
        assert!(json.contains("actor1"));

        let mut log2 = AuditLog::new();
        let imported = log2.import_json(&json).unwrap();
        assert_eq!(imported, 2);
        assert_eq!(log2.entry_count(), 2);
        assert_eq!(log2.get_entry(0).unwrap().actor, "actor1");
        assert_eq!(log2.get_entry(1).unwrap().actor, "actor2");
    }

    #[test]
    fn test_entry_count() {
        let mut log = AuditLog::new();
        assert_eq!(log.entry_count(), 0);

        log.append("a", "actor", "t", sample_details()).unwrap();
        assert_eq!(log.entry_count(), 1);

        log.append("b", "actor", "t", sample_details()).unwrap();
        assert_eq!(log.entry_count(), 2);
    }

    #[test]
    fn test_get_entry_by_sequence() {
        let mut log = AuditLog::new();
        log.append("first", "a1", "t", sample_details())
            .unwrap();
        log.append("second", "a2", "t", sample_details())
            .unwrap();

        let e0 = log.get_entry(0).unwrap();
        assert_eq!(e0.action, "first");

        let e1 = log.get_entry(1).unwrap();
        assert_eq!(e1.action, "second");

        assert!(log.get_entry(2).is_none());
    }

    #[test]
    fn test_last_entry() {
        let mut log = AuditLog::new();
        assert!(log.last_entry().is_none());

        log.append("first", "a", "t", sample_details()).unwrap();
        assert_eq!(log.last_entry().unwrap().action, "first");

        log.append("second", "a", "t", sample_details()).unwrap();
        assert_eq!(log.last_entry().unwrap().action, "second");
    }

    #[test]
    fn test_with_config_respects_max_entries() {
        let config = AuditConfig {
            max_entries: 3,
            sign_entries: false,
        };
        let mut log = AuditLog::with_config(config);

        log.append("a", "actor", "t", sample_details()).unwrap();
        log.append("b", "actor", "t", sample_details()).unwrap();
        log.append("c", "actor", "t", sample_details()).unwrap();

        let result = log.append("d", "actor", "t", sample_details());
        assert!(result.is_err());
        assert_eq!(log.entry_count(), 3);
    }

    #[test]
    fn test_unique_hashes_per_entry() {
        let mut log = AuditLog::new();
        let mut hashes = std::collections::HashSet::new();

        for i in 0..10 {
            let mut details = sample_details();
            details.insert("i".into(), serde_json::json!(i));
            let entry = log
                .append(&format!("action_{}", i), "actor", "target", details)
                .unwrap();
            assert!(hashes.insert(entry.current_hash.clone()), "Hash {} already seen", entry.current_hash);
        }
    }

    #[test]
    fn test_hash_includes_previous_hash() {
        let mut log = AuditLog::new();
        let e1 = log.append("a", "actor", "t", sample_details()).unwrap();
        let e2 = log.append("a", "actor", "t", sample_details()).unwrap();

        let details_json = serde_json::to_string(&sample_details()).unwrap();
        assert_eq!(e2.previous_hash, e1.current_hash);
        let input_recompute = format!(
            "{}{}{}{}{}{}",
            e2.previous_hash, e2.action, e2.actor, e2.target, e2.timestamp, details_json
        );
        let mut hasher = Sha3_256::new();
        hasher.update(input_recompute.as_bytes());
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(e2.current_hash, expected);
    }

    #[test]
    fn test_import_json_rejects_invalid() {
        let mut log = AuditLog::new();
        let result = log.import_json("not valid json");
        assert!(result.is_err());
    }
}
