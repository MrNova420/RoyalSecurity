use redb::*;
use serde::{Serialize, Deserialize};

pub const EVENTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("events");

pub const PROCESSES_TABLE: TableDefinition<u32, &[u8]> = TableDefinition::new("processes");

pub const NETWORK_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("network_connections");

pub const THREATS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("threats");

pub const AUDIT_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("audit_log");

pub const RULES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("rules");

pub const IOCS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("iocs");

pub const CONFIG_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("config_overrides");

pub const MODULES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("module_health");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub event_type: String,
    pub source: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub user: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredThreat {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    pub description: String,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIoc {
    pub value: String,
    pub ioc_type: String,
    pub confidence: f64,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub tags: Vec<String>,
}
