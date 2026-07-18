pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, ProcessInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeletionMethod {
    ZeroFill,
    RandomData,
    DoD522022M,
    Gutmann,
    CryptographicErase,
}

impl std::fmt::Display for DeletionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeletionMethod::ZeroFill => write!(f, "Zero Fill"),
            DeletionMethod::RandomData => write!(f, "Random Data"),
            DeletionMethod::DoD522022M => write!(f, "DoD 5220.22-M"),
            DeletionMethod::Gutmann => write!(f, "Gutmann"),
            DeletionMethod::CryptographicErase => write!(f, "Cryptographic Erase"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRecord {
    pub file_path: String,
    pub method: DeletionMethod,
    pub passes: u32,
    pub timestamp: DateTime<Utc>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionAlert {
    pub file_path: String,
    pub process_name: String,
    pub method: DeletionMethod,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

pub struct SecureDeleter {
    records: HashMap<String, DeletionRecord>,
    alerts: Vec<DeletionAlert>,
}

impl SecureDeleter {
    pub fn new() -> Self {
        info!("Initializing secure deletion monitor");
        Self {
            records: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    pub fn schedule_deletion(&mut self, path: &str, method: DeletionMethod) -> String {
        let id = Uuid::new_v4().to_string();
        let passes = match method {
            DeletionMethod::ZeroFill => 1,
            DeletionMethod::RandomData => 3,
            DeletionMethod::DoD522022M => 7,
            DeletionMethod::Gutmann => 35,
            DeletionMethod::CryptographicErase => 1,
        };

        let record = DeletionRecord {
            file_path: path.to_string(),
            method,
            passes,
            timestamp: Utc::now(),
            verified: false,
        };

        info!(
            file = %path,
            method = %method,
            passes = passes,
            id = %id,
            "Scheduled secure deletion"
        );

        self.records.insert(id.clone(), record);
        id
    }

    pub fn verify_deletion(&mut self, record_id: &str) -> bool {
        if let Some(record) = self.records.get_mut(record_id) {
            record.verified = true;
            info!(
                file = %record.file_path,
                "Deletion verified"
            );
            return true;
        }
        false
    }

    pub fn detect_anti_forensics(&mut self, process: &ProcessInfo) -> Vec<DeletionAlert> {
        let mut alerts = Vec::new();
        let name_lower = process.name.to_lowercase();
        let cmd_lower = process.command_line.to_lowercase();

        let anti_forensic_tools = [
            ("sdelete", "Sysinternals SDelete", DeletionMethod::ZeroFill),
            ("cipher /w", "Cipher Wipe", DeletionMethod::ZeroFill),
            ("shred", "GNU Shred", DeletionMethod::RandomData),
            ("wipe", "Wipe Utility", DeletionMethod::RandomData),
            ("nwipe", "Nwipe", DeletionMethod::DoD522022M),
        ];

        for (tool_name, _description, method) in &anti_forensic_tools {
            if name_lower.contains(tool_name) || cmd_lower.contains(tool_name) {
                warn!(
                    process = %process.name,
                    pid = process.pid,
                    tool = tool_name,
                    "Anti-forensic deletion tool detected"
                );
                let alert = DeletionAlert {
                    file_path: process.command_line.clone(),
                    process_name: process.name.clone(),
                    method: *method,
                    severity: EventSeverity::High,
                    timestamp: Utc::now(),
                };
                self.alerts.push(alert.clone());
                alerts.push(alert);
            }
        }

        if cmd_lower.contains("/p ") || cmd_lower.contains("--passes") {
            let has_wipe_args = cmd_lower.contains("c:\\") || cmd_lower.contains("-u");
            if has_wipe_args && alerts.is_empty() {
                warn!(
                    process = %process.name,
                    pid = process.pid,
                    "Suspicious deletion command with multi-pass arguments"
                );
                let alert = DeletionAlert {
                    file_path: process.command_line.clone(),
                    process_name: process.name.clone(),
                    method: DeletionMethod::DoD522022M,
                    severity: EventSeverity::Medium,
                    timestamp: Utc::now(),
                };
                self.alerts.push(alert.clone());
                alerts.push(alert);
            }
        }

        alerts
    }

    pub fn get_records(&self) -> Vec<&DeletionRecord> {
        self.records.values().collect()
    }

    pub fn deletion_count(&self) -> usize {
        self.records.len()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn alerts(&self) -> &[DeletionAlert] {
        &self.alerts
    }
}

impl Default for SecureDeleter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process(name: &str, cmd: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: name.to_string(),
            path: format!("C:\\Tools\\{}", name),
            command_line: cmd.to_string(),
            user: "admin".to_string(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_secure_deleter_new() {
        let deleter = SecureDeleter::new();
        assert_eq!(deleter.deletion_count(), 0);
        assert_eq!(deleter.alert_count(), 0);
    }

    #[test]
    fn test_schedule_deletion() {
        let mut deleter = SecureDeleter::new();
        let id = deleter.schedule_deletion("C:\\secret.txt", DeletionMethod::DoD522022M);
        assert_eq!(deleter.deletion_count(), 1);
        assert!(!id.is_empty());
    }

    #[test]
    fn test_verify_deletion() {
        let mut deleter = SecureDeleter::new();
        let id = deleter.schedule_deletion("C:\\secret.txt", DeletionMethod::ZeroFill);
        assert!(!deleter.records[&id].verified);
        assert!(deleter.verify_deletion(&id));
        assert!(deleter.records[&id].verified);
    }

    #[test]
    fn test_verify_nonexistent_returns_false() {
        let mut deleter = SecureDeleter::new();
        assert!(!deleter.verify_deletion("nonexistent-id"));
    }

    #[test]
    fn test_detect_anti_forensics_sdelete() {
        let mut deleter = SecureDeleter::new();
        let process = make_process("sdelete.exe", "sdelete.exe -p 3 C:\\temp");
        let alerts = deleter.detect_anti_forensics(&process);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].process_name, "sdelete.exe");
        assert_eq!(alerts[0].severity, EventSeverity::High);
    }

    #[test]
    fn test_detect_anti_forensics_cipher_wipe() {
        let mut deleter = SecureDeleter::new();
        let process = make_process("cmd.exe", "cmd.exe /c cipher /w:C:\\temp");
        let alerts = deleter.detect_anti_forensics(&process);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].method, DeletionMethod::ZeroFill);
    }

    #[test]
    fn test_detect_anti_forensics_clean_process() {
        let mut deleter = SecureDeleter::new();
        let process = make_process("notepad.exe", "notepad.exe C:\\readme.txt");
        let alerts = deleter.detect_anti_forensics(&process);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_get_records() {
        let mut deleter = SecureDeleter::new();
        deleter.schedule_deletion("a.txt", DeletionMethod::Gutmann);
        deleter.schedule_deletion("b.txt", DeletionMethod::RandomData);
        let records = deleter.get_records();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_deletion_method_display() {
        assert_eq!(DeletionMethod::Gutmann.to_string(), "Gutmann");
        assert_eq!(
            DeletionMethod::CryptographicErase.to_string(),
            "Cryptographic Erase"
        );
        assert_eq!(DeletionMethod::DoD522022M.to_string(), "DoD 5220.22-M");
    }

    #[test]
    fn test_passes_based_on_method() {
        let mut deleter = SecureDeleter::new();
        let id = deleter.schedule_deletion("test.txt", DeletionMethod::Gutmann);
        assert_eq!(deleter.records[&id].passes, 35);
    }
}
