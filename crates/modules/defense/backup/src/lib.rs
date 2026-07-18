pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("Backup not found: {0}")]
    NotFound(String),
    #[error("Backup integrity check failed: {0}")]
    IntegrityFailed(String),
    #[error("VSS tampering detected: {0}")]
    VssTampering(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum BackupStatus {
    Valid,
    Corrupted,
    Missing,
    Tampered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub path: String,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
    pub hash: String,
    pub status: BackupStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupAlertType {
    TamperingDetected,
    BackupDeleted,
    VssTampering,
    IntegrityFailure,
    RansomwareIndicator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupAlert {
    pub alert_type: BackupAlertType,
    pub backup_id: String,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshot {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub volume: String,
    pub size_bytes: u64,
    pub integrity_hash: String,
    pub is_tampered: bool,
}

pub struct BackupMonitor {
    backups: HashMap<String, BackupInfo>,
    alerts: Vec<BackupAlert>,
    vss_snapshots: HashMap<String, VssSnapshot>,
    deletion_events: Vec<(String, DateTime<Utc>)>,
    max_backups: usize,
}

impl BackupMonitor {
    pub fn new() -> Self {
        info!("Initializing Backup Integrity monitor");
        Self {
            backups: HashMap::new(),
            alerts: Vec::new(),
            vss_snapshots: HashMap::new(),
            deletion_events: Vec::new(),
            max_backups: 1000,
        }
    }

    pub fn register_backup(&mut self, info: BackupInfo) {
        info!(id = %info.id, path = %info.path, size = info.size, "Registering backup");
        self.backups.insert(info.id.clone(), info);
    }

    pub fn verify_integrity(&self, backup_id: &str) -> bool {
        match self.backups.get(backup_id) {
            Some(backup) => backup.status == BackupStatus::Valid && !backup.hash.is_empty(),
            None => false,
        }
    }

    pub fn detect_backup_tampering(&mut self, backup_id: &str, current_hash: &str) -> Option<BackupAlert> {
        let backup = self.backups.get(backup_id)?;

        if backup.hash != current_hash {
            let alert = BackupAlert {
                alert_type: BackupAlertType::TamperingDetected,
                backup_id: backup_id.to_string(),
                message: format!(
                    "Backup {} tampering detected: expected hash {}, got {}",
                    backup_id, backup.hash, current_hash
                ),
                severity: EventSeverity::Critical,
                timestamp: Utc::now(),
            };

            if let Some(b) = self.backups.get_mut(backup_id) {
                b.status = BackupStatus::Tampered;
            }

            warn!(backup_id = %backup_id, "Backup tampering detected");
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    pub fn detect_backup_deletion(&mut self, backup_id: &str) -> Option<BackupAlert> {
        if let Some(backup) = self.backups.remove(backup_id) {
            self.deletion_events.push((backup_id.to_string(), Utc::now()));

            let recent_deletions = self.deletion_events
                .iter()
                .filter(|(_, t)| {
                    Utc::now().signed_duration_since(*t).num_seconds() < 300
                })
                .count();

            let severity = if recent_deletions >= 3 {
                EventSeverity::Critical
            } else {
                EventSeverity::High
            };

            let alert = BackupAlert {
                alert_type: BackupAlertType::BackupDeleted,
                backup_id: backup_id.to_string(),
                message: format!(
                    "Backup {} deleted (path: {}) - {} recent deletions in window",
                    backup_id, backup.path, recent_deletions
                ),
                severity,
                timestamp: Utc::now(),
            };

            if recent_deletions >= 3 {
                warn!(
                    deletions = recent_deletions,
                    "Multiple backup deletions detected - possible ransomware"
                );
                let ransomware_alert = BackupAlert {
                    alert_type: BackupAlertType::RansomwareIndicator,
                    backup_id: backup_id.to_string(),
                    message: format!(
                        "Ransomware indicator: {} backups deleted within 5 minutes",
                        recent_deletions
                    ),
                    severity: EventSeverity::Critical,
                    timestamp: Utc::now(),
                };
                self.alerts.push(ransomware_alert);
            }

            warn!(backup_id = %backup_id, "Backup deletion detected");
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    pub fn detect_vss_tampering(&mut self, snapshot_id: &str, current_hash: &str) -> Option<BackupAlert> {
        let snapshot = self.vss_snapshots.get(snapshot_id)?;

        if snapshot.integrity_hash != current_hash {
            if let Some(s) = self.vss_snapshots.get_mut(snapshot_id) {
                s.is_tampered = true;
            }

            let volume = self.vss_snapshots.get(snapshot_id).map(|s| s.volume.clone()).unwrap_or_default();
            let alert = BackupAlert {
                alert_type: BackupAlertType::VssTampering,
                backup_id: snapshot_id.to_string(),
                message: format!(
                    "VSS snapshot {} tampering detected on volume {}",
                    snapshot_id, volume
                ),
                severity: EventSeverity::Critical,
                timestamp: Utc::now(),
            };

            warn!(snapshot_id = %snapshot_id, "VSS tampering detected");
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    pub fn register_vss_snapshot(&mut self, snapshot: VssSnapshot) {
        info!(id = %snapshot.id, volume = %snapshot.volume, "Registering VSS snapshot");
        self.vss_snapshots.insert(snapshot.id.clone(), snapshot);
    }

    pub fn get_backups(&self) -> Vec<&BackupInfo> {
        self.backups.values().collect()
    }

    pub fn get_alerts(&self) -> &[BackupAlert] {
        &self.alerts
    }

    pub fn get_vss_snapshots(&self) -> Vec<&VssSnapshot> {
        self.vss_snapshots.values().collect()
    }
}

impl Default for BackupMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backup(id: &str, hash: &str) -> BackupInfo {
        BackupInfo {
            id: id.to_string(),
            path: format!("C:\\Backups\\{}.bak", id),
            timestamp: Utc::now(),
            size: 1024 * 1024,
            hash: hash.to_string(),
            status: BackupStatus::Valid,
        }
    }

    #[test]
    fn test_backup_monitor_new() {
        let monitor = BackupMonitor::new();
        assert!(monitor.get_backups().is_empty());
        assert!(monitor.get_alerts().is_empty());
    }

    #[test]
    fn test_register_backup() {
        let mut monitor = BackupMonitor::new();
        let backup = make_backup("bk001", "abc123hash");
        monitor.register_backup(backup);
        assert_eq!(monitor.get_backups().len(), 1);
        assert!(monitor.verify_integrity("bk001"));
    }

    #[test]
    fn test_verify_integrity_valid() {
        let mut monitor = BackupMonitor::new();
        monitor.register_backup(make_backup("bk002", "hash_valid"));
        assert!(monitor.verify_integrity("bk002"));
    }

    #[test]
    fn test_verify_integrity_missing() {
        let monitor = BackupMonitor::new();
        assert!(!monitor.verify_integrity("nonexistent"));
    }

    #[test]
    fn test_detect_backup_tampering() {
        let mut monitor = BackupMonitor::new();
        monitor.register_backup(make_backup("bk003", "original_hash"));
        let alert = monitor.detect_backup_tampering("bk003", "tampered_hash");
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, BackupAlertType::TamperingDetected);
        assert_eq!(alert.severity, EventSeverity::Critical);
        assert_eq!(monitor.get_alerts().len(), 1);
    }

    #[test]
    fn test_detect_backup_no_tampering() {
        let mut monitor = BackupMonitor::new();
        monitor.register_backup(make_backup("bk004", "same_hash"));
        let alert = monitor.detect_backup_tampering("bk004", "same_hash");
        assert!(alert.is_none());
        assert!(monitor.get_alerts().is_empty());
    }

    #[test]
    fn test_detect_backup_deletion() {
        let mut monitor = BackupMonitor::new();
        monitor.register_backup(make_backup("bk005", "hash5"));
        let alert = monitor.detect_backup_deletion("bk005");
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, BackupAlertType::BackupDeleted);
        assert!(monitor.get_backups().is_empty());
    }

    #[test]
    fn test_detect_ransomware_deletion_pattern() {
        let mut monitor = BackupMonitor::new();
        for i in 0..4 {
            monitor.register_backup(make_backup(&format!("bk_r{:03}", i), &format!("hash{}", i)));
        }
        for i in 0..4 {
            monitor.detect_backup_deletion(&format!("bk_r{:03}", i));
        }
        let alerts = monitor.get_alerts();
        let ransomware_alerts: Vec<_> = alerts
            .iter()
            .filter(|a| a.alert_type == BackupAlertType::RansomwareIndicator)
            .collect();
        assert!(!ransomware_alerts.is_empty());
    }

    #[test]
    fn test_register_and_get_vss_snapshot() {
        let mut monitor = BackupMonitor::new();
        let snapshot = VssSnapshot {
            id: "snap001".to_string(),
            created_at: Utc::now(),
            volume: "C:".to_string(),
            size_bytes: 50 * 1024 * 1024,
            integrity_hash: "snap_hash_abc".to_string(),
            is_tampered: false,
        };
        monitor.register_vss_snapshot(snapshot);
        assert_eq!(monitor.get_vss_snapshots().len(), 1);
    }

    #[test]
    fn test_detect_vss_tampering() {
        let mut monitor = BackupMonitor::new();
        let snapshot = VssSnapshot {
            id: "snap002".to_string(),
            created_at: Utc::now(),
            volume: "D:".to_string(),
            size_bytes: 100 * 1024 * 1024,
            integrity_hash: "original_hash".to_string(),
            is_tampered: false,
        };
        monitor.register_vss_snapshot(snapshot);
        let alert = monitor.detect_vss_tampering("snap002", "modified_hash");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().alert_type, BackupAlertType::VssTampering);
    }

    #[test]
    fn test_multiple_backups_independent() {
        let mut monitor = BackupMonitor::new();
        monitor.register_backup(make_backup("a", "hash_a"));
        monitor.register_backup(make_backup("b", "hash_b"));
        assert_eq!(monitor.get_backups().len(), 2);
        monitor.detect_backup_tampering("a", "wrong");
        assert!(monitor.verify_integrity("b"));
    }
}
