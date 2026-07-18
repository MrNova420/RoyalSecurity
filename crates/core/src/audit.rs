use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use tracing::info;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub target: String,
    pub details: HashMap<String, serde_json::Value>,
    pub previous_hash: String,
    pub current_hash: String,
}

pub struct AuditLog {
    entries: Vec<AuditEntry>,
    last_hash: String,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: "GENESIS".to_string(),
        }
    }

    pub fn record(&mut self, action: &str, actor: &str, target: &str, details: HashMap<String, serde_json::Value>) -> AuditEntry {
        let entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: action.to_string(),
            actor: actor.to_string(),
            target: target.to_string(),
            details,
            previous_hash: self.last_hash.clone(),
            current_hash: String::new(),
        };

        let hash = self.compute_hash(&entry);
        let mut entry = entry;
        entry.current_hash = hash.clone();
        self.last_hash = hash.clone();
        self.entries.push(entry.clone());

        info!(audit_id = %entry.id, action = %action, "Audit entry recorded");
        entry
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = "GENESIS".to_string();
        for entry in &self.entries {
            if entry.previous_hash != prev_hash {
                return false;
            }
            let computed = self.compute_hash(entry);
            if computed != entry.current_hash {
                return false;
            }
            prev_hash = entry.current_hash.clone();
        }
        true
    }

    fn compute_hash(&self, entry: &AuditEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&entry.previous_hash);
        hasher.update(entry.timestamp.to_rfc3339());
        hasher.update(&entry.action);
        hasher.update(&entry.actor);
        hasher.update(&entry.target);
        hasher.update(serde_json::to_string(&entry.details).unwrap_or_default());
        hex::encode(hasher.finalize())
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }
}
