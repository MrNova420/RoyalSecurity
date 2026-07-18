pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption check failed: {0}")]
    CheckFailed(String),
    #[error("Ransomware indicator detected: {0}")]
    RansomwareDetected(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum RansomwareEncryptionIndicator {
    MassEncryption,
    UnusualAlgorithm,
    KeyExchangeAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStatus {
    pub path: String,
    pub encrypted: bool,
    pub algorithm: Option<String>,
    pub key_id: Option<String>,
    pub encrypted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionEvent {
    pub path: String,
    pub algorithm: String,
    pub timestamp: DateTime<Utc>,
    pub user: Option<String>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionAlert {
    pub indicator: RansomwareEncryptionIndicator,
    pub description: String,
    pub severity: EventSeverity,
    pub affected_paths: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitlockerStatus {
    pub volume: String,
    pub encrypted: bool,
    pub encryption_method: Option<String>,
    pub protection_status: String,
    pub conversion_status: Option<String>,
}

pub struct EncryptionMonitor {
    encrypted_files: HashMap<String, EncryptionStatus>,
    encryption_events: Vec<EncryptionEvent>,
    alerts: Vec<EncryptionAlert>,
    event_window: Vec<EncryptionEvent>,
    known_safe_algorithms: Vec<String>,
    mass_encryption_threshold: usize,
}

impl EncryptionMonitor {
    pub fn new() -> Self {
        info!("Initializing Encryption-at-Rest monitor");
        Self {
            encrypted_files: HashMap::new(),
            encryption_events: Vec::new(),
            alerts: Vec::new(),
            event_window: Vec::new(),
            known_safe_algorithms: vec![
                "AES-256".to_string(),
                "AES-128".to_string(),
                "AES-256-XTS".to_string(),
                "BitLocker".to_string(),
                "EFS".to_string(),
            ],
            mass_encryption_threshold: 50,
        }
    }

    pub fn check_file_encryption(&self, path: &str) -> EncryptionStatus {
        self.encrypted_files.get(path).cloned().unwrap_or(EncryptionStatus {
            path: path.to_string(),
            encrypted: false,
            algorithm: None,
            key_id: None,
            encrypted_at: None,
        })
    }

    pub fn track_encryption_event(&mut self, path: &str, algorithm: &str) -> Vec<EncryptionAlert> {
        let mut alerts = Vec::new();

        let event = EncryptionEvent {
            path: path.to_string(),
            algorithm: algorithm.to_string(),
            timestamp: Utc::now(),
            user: None,
            process: None,
        };

        self.encryption_events.push(event.clone());
        self.event_window.push(event);

        let now = Utc::now();
        self.event_window.retain(|e| {
            now.signed_duration_since(e.timestamp).num_seconds() < 300
        });

        let status = EncryptionStatus {
            path: path.to_string(),
            encrypted: true,
            algorithm: Some(algorithm.to_string()),
            key_id: None,
            encrypted_at: Some(Utc::now()),
        };
        self.encrypted_files.insert(path.to_string(), status);

        if !self.known_safe_algorithms.iter().any(|a| a.eq_ignore_ascii_case(algorithm)) {
            let alert = EncryptionAlert {
                indicator: RansomwareEncryptionIndicator::UnusualAlgorithm,
                description: format!(
                    "Unusual encryption algorithm '{}' used on '{}' - possible ransomware",
                    algorithm, path
                ),
                severity: EventSeverity::High,
                affected_paths: vec![path.to_string()],
                timestamp: Utc::now(),
            };
            warn!(path = %path, algorithm = %algorithm, "Unusual encryption algorithm detected");
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        if self.event_window.len() >= self.mass_encryption_threshold {
            let affected: Vec<String> = self.event_window.iter().map(|e| e.path.clone()).collect();
            let alert = EncryptionAlert {
                indicator: RansomwareEncryptionIndicator::MassEncryption,
                description: format!(
                    "Mass encryption detected: {} files encrypted within 5 minutes - ransomware suspected",
                    self.event_window.len()
                ),
                severity: EventSeverity::Critical,
                affected_paths: affected,
                timestamp: Utc::now(),
            };
            warn!(
                count = self.event_window.len(),
                "Mass encryption detected - possible ransomware"
            );
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        alerts
    }

    pub fn detect_mass_encryption(&self, events: &[EncryptionEvent]) -> Option<EncryptionAlert> {
        if events.len() < self.mass_encryption_threshold {
            return None;
        }

        let first_ts = events.first()?.timestamp;
        let last_ts = events.last()?.timestamp;
        let time_span = last_ts.signed_duration_since(first_ts).num_seconds();

        if time_span > 300 {
            return None;
        }

        let unique_algorithms: std::collections::HashSet<&str> = events.iter()
            .map(|e| e.algorithm.as_str())
            .collect();

        let indicator = if unique_algorithms.len() == 1 {
            RansomwareEncryptionIndicator::MassEncryption
        } else {
            RansomwareEncryptionIndicator::KeyExchangeAnomaly
        };

        Some(EncryptionAlert {
            indicator,
            description: format!(
                "Mass encryption detected: {} events in {} seconds using {} algorithm(s)",
                events.len(), time_span, unique_algorithms.len()
            ),
            severity: EventSeverity::Critical,
            affected_paths: events.iter().map(|e| e.path.clone()).collect(),
            timestamp: Utc::now(),
        })
    }

    pub fn get_encrypted_files(&self) -> Vec<&EncryptionStatus> {
        self.encrypted_files.values().collect()
    }

    pub fn get_encrypted_count(&self) -> usize {
        self.encrypted_files.len()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn get_alerts(&self) -> &[EncryptionAlert] {
        &self.alerts
    }

    pub fn clear_event_window(&mut self) {
        self.event_window.clear();
    }

    pub fn set_mass_encryption_threshold(&mut self, threshold: usize) {
        self.mass_encryption_threshold = threshold;
    }

    pub fn add_known_algorithm(&mut self, algorithm: &str) {
        self.known_safe_algorithms.push(algorithm.to_string());
    }
}

impl Default for EncryptionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_monitor_new() {
        let monitor = EncryptionMonitor::new();
        assert!(monitor.alert_count() == 0);
        assert!(monitor.get_encrypted_files().is_empty());
    }

    #[test]
    fn test_check_file_not_encrypted() {
        let monitor = EncryptionMonitor::new();
        let status = monitor.check_file_encryption("/test/file.txt");
        assert!(!status.encrypted);
        assert!(status.algorithm.is_none());
    }

    #[test]
    fn test_track_encryption_event_known_algo() {
        let mut monitor = EncryptionMonitor::new();
        let alerts = monitor.track_encryption_event("/docs/report.docx", "AES-256");
        assert!(alerts.is_empty());
        let status = monitor.check_file_encryption("/docs/report.docx");
        assert!(status.encrypted);
        assert_eq!(status.algorithm.as_deref(), Some("AES-256"));
    }

    #[test]
    fn test_track_encryption_event_unknown_algo() {
        let mut monitor = EncryptionMonitor::new();
        let alerts = monitor.track_encryption_event("/docs/secret.xlsx", "XOR-4096");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].indicator, RansomwareEncryptionIndicator::UnusualAlgorithm);
    }

    #[test]
    fn test_mass_encryption_detection() {
        let mut monitor = EncryptionMonitor::new();
        monitor.set_mass_encryption_threshold(5);
        let now = Utc::now();
        let events: Vec<EncryptionEvent> = (0..6)
            .map(|i| EncryptionEvent {
                path: format!("/files/file_{}.dat", i),
                algorithm: "AES-256".to_string(),
                timestamp: now,
                user: None,
                process: None,
            })
            .collect();
        let alert = monitor.detect_mass_encryption(&events);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().indicator, RansomwareEncryptionIndicator::MassEncryption);
    }

    #[test]
    fn test_mass_encryption_not_enough_events() {
        let monitor = EncryptionMonitor::new();
        let now = Utc::now();
        let events: Vec<EncryptionEvent> = (0..3)
            .map(|i| EncryptionEvent {
                path: format!("/files/file_{}.dat", i),
                algorithm: "AES-256".to_string(),
                timestamp: now,
                user: None,
                process: None,
            })
            .collect();
        assert!(monitor.detect_mass_encryption(&events).is_none());
    }

    #[test]
    fn test_get_encrypted_files() {
        let mut monitor = EncryptionMonitor::new();
        monitor.track_encryption_event("/a.txt", "AES-256");
        monitor.track_encryption_event("/b.txt", "AES-128");
        assert_eq!(monitor.get_encrypted_files().len(), 2);
        assert_eq!(monitor.get_encrypted_count(), 2);
    }

    #[test]
    fn test_clear_event_window() {
        let mut monitor = EncryptionMonitor::new();
        monitor.track_encryption_event("/a.txt", "AES-256");
        monitor.clear_event_window();
        assert!(monitor.event_window.is_empty());
    }

    #[test]
    fn test_multiple_unusual_algo_alerts() {
        let mut monitor = EncryptionMonitor::new();
        monitor.track_encryption_event("/a.txt", "RC4");
        monitor.track_encryption_event("/b.txt", "DES");
        assert_eq!(monitor.alert_count(), 2);
    }
}
