pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeceptionError {
    #[error("Decoy not found: {0}")]
    NotFound(String),
    #[error("Decoy deployment failed: {0}")]
    DeploymentFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DecoyType {
    File,
    Service,
    User,
    Share,
    Registry,
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyAsset {
    pub id: String,
    pub asset_type: DecoyType,
    pub name: String,
    pub tripwire: bool,
    pub deployed_at: DateTime<Utc>,
    pub last_checked: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeceptionAlertType {
    DecoyAccessed,
    DecoyModified,
    DecoyEnumerated,
    DecoyCredentialUsed,
    DecoyServiceQueried,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionAlert {
    pub alert_type: DeceptionAlertType,
    pub decoy_id: String,
    pub decoy_name: String,
    pub source: String,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionRecord {
    pub decoy_id: String,
    pub source: String,
    pub interaction_type: DeceptionAlertType,
    pub timestamp: DateTime<Utc>,
}

pub struct DeceptionEngine {
    decoys: HashMap<String, DecoyAsset>,
    interactions: Vec<InteractionRecord>,
    alerts: Vec<DeceptionAlert>,
    decoy_counter: u64,
    tripwire_states: HashMap<String, bool>,
}

impl DeceptionEngine {
    pub fn new() -> Self {
        info!("Initializing Deception/Honeypot engine");
        Self {
            decoys: HashMap::new(),
            interactions: Vec::new(),
            alerts: Vec::new(),
            decoy_counter: 0,
            tripwire_states: HashMap::new(),
        }
    }

    pub fn deploy_decoy(&mut self, decoy_type: DecoyType, name: &str) -> String {
        self.decoy_counter += 1;
        let id = format!("decoy_{:06}", self.decoy_counter);

        let decoy = DecoyAsset {
            id: id.clone(),
            asset_type: decoy_type,
            name: name.to_string(),
            tripwire: true,
            deployed_at: Utc::now(),
            last_checked: None,
        };

        info!(id = %id, name = %name, type_ = ?decoy_type, "Deploying decoy asset");
        self.decoys.insert(id.clone(), decoy);
        self.tripwire_states.insert(id.clone(), false);

        id
    }

    pub fn check_interaction(&mut self, decoy_id: &str, source: &str) -> Option<DeceptionAlert> {
        let decoy = self.decoys.get(decoy_id)?;

        if !decoy.tripwire {
            return None;
        }

        let interaction_type = match decoy.asset_type {
            DecoyType::File => DeceptionAlertType::DecoyAccessed,
            DecoyType::Service => DeceptionAlertType::DecoyServiceQueried,
            DecoyType::User => DeceptionAlertType::DecoyCredentialUsed,
            DecoyType::Share => DeceptionAlertType::DecoyEnumerated,
            DecoyType::Registry => DeceptionAlertType::DecoyModified,
            DecoyType::Memory => DeceptionAlertType::DecoyAccessed,
        };

        if let Some(tripped) = self.tripwire_states.get_mut(decoy_id) {
            *tripped = true;
        }

        let record = InteractionRecord {
            decoy_id: decoy_id.to_string(),
            source: source.to_string(),
            interaction_type,
            timestamp: Utc::now(),
        };
        self.interactions.push(record);

        let decoy_name = decoy.name.clone();
        let asset_type = decoy.asset_type;

        let alert = DeceptionAlert {
            alert_type: interaction_type,
            decoy_id: decoy_id.to_string(),
            decoy_name: decoy_name.clone(),
            source: source.to_string(),
            message: format!(
                "Decoy {:?} '{}' interacted by source '{}'",
                asset_type, decoy_name, source
            ),
            severity: EventSeverity::Critical,
            timestamp: Utc::now(),
        };

        warn!(
            decoy_id = %decoy_id,
            decoy_name = %decoy_name,
            source = %source,
            "Decoy interaction detected"
        );

        self.alerts.push(alert.clone());
        Some(alert)
    }

    pub fn active_decoys(&self) -> Vec<&DecoyAsset> {
        self.decoys.values().collect()
    }

    pub fn remove_decoy(&mut self, id: &str) -> bool {
        if let Some(decoy) = self.decoys.remove(id) {
            self.tripwire_states.remove(id);
            info!(id = %id, name = %decoy.name, "Removing decoy asset");
            true
        } else {
            false
        }
    }

    pub fn is_tripped(&self, decoy_id: &str) -> bool {
        self.tripwire_states.get(decoy_id).copied().unwrap_or(false)
    }

    pub fn get_interactions(&self) -> &[InteractionRecord] {
        &self.interactions
    }

    pub fn get_alerts(&self) -> &[DeceptionAlert] {
        &self.alerts
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn get_interactions_by_source(&self, source: &str) -> Vec<&InteractionRecord> {
        self.interactions.iter().filter(|i| i.source == source).collect()
    }
}

impl Default for DeceptionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deception_engine_new() {
        let engine = DeceptionEngine::new();
        assert!(engine.active_decoys().is_empty());
        assert!(engine.alert_count() == 0);
    }

    #[test]
    fn test_deploy_file_decoy() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy_decoy(DecoyType::File, "passwords.docx");
        assert!(!id.is_empty());
        assert_eq!(engine.active_decoys().len(), 1);
        assert_eq!(engine.active_decoys()[0].name, "passwords.docx");
    }

    #[test]
    fn test_deploy_multiple_decoys() {
        let mut engine = DeceptionEngine::new();
        engine.deploy_decoy(DecoyType::File, "secret.txt");
        engine.deploy_decoy(DecoyType::Service, "FakeSQL");
        engine.deploy_decoy(DecoyType::User, "admin_backup");
        assert_eq!(engine.active_decoys().len(), 3);
    }

    #[test]
    fn test_check_interaction_triggers_alert() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy_decoy(DecoyType::File, "honey_token.xlsx");
        let alert = engine.check_interaction(&id, "10.0.0.99");
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, EventSeverity::Critical);
        assert!(alert.source == "10.0.0.99");
        assert!(engine.is_tripped(&id));
    }

    #[test]
    fn test_check_interaction_nonexistent() {
        let mut engine = DeceptionEngine::new();
        let alert = engine.check_interaction("nonexistent", "source");
        assert!(alert.is_none());
    }

    #[test]
    fn test_remove_decoy() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy_decoy(DecoyType::Registry, "HKLM\\FAKE");
        assert!(engine.remove_decoy(&id));
        assert!(engine.active_decoys().is_empty());
        assert!(!engine.remove_decoy(&id));
    }

    #[test]
    fn test_get_interactions_by_source() {
        let mut engine = DeceptionEngine::new();
        let id1 = engine.deploy_decoy(DecoyType::Share, "\\\\fake\\share");
        let id2 = engine.deploy_decoy(DecoyType::File, "decoy.pdf");
        engine.check_interaction(&id1, "attacker");
        engine.check_interaction(&id2, "attacker");
        engine.check_interaction(&id2, "other");

        let attacker_interactions = engine.get_interactions_by_source("attacker");
        assert_eq!(attacker_interactions.len(), 2);
    }

    #[test]
    fn test_service_decoy_interaction() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy_decoy(DecoyType::Service, "FakeSSH");
        let alert = engine.check_interaction(&id, "scanner");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().alert_type, DeceptionAlertType::DecoyServiceQueried);
    }

    #[test]
    fn test_user_decoy_interaction() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy_decoy(DecoyType::User, "svc_backup_old");
        let alert = engine.check_interaction(&id, "lateral_host");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().alert_type, DeceptionAlertType::DecoyCredentialUsed);
    }

    #[test]
    fn test_multiple_interactions_accumulate() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy_decoy(DecoyType::Memory, "fake_mem_region");
        for _ in 0..5 {
            engine.check_interaction(&id, "scanner");
        }
        assert_eq!(engine.get_interactions().len(), 5);
        assert_eq!(engine.alert_count(), 5);
    }
}
