pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FdeStatus {
    Encrypted,
    Encrypting,
    Decrypted,
    Suspended,
    Recovery,
}

impl std::fmt::Display for FdeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FdeStatus::Encrypted => write!(f, "Encrypted"),
            FdeStatus::Encrypting => write!(f, "Encrypting"),
            FdeStatus::Decrypted => write!(f, "Decrypted"),
            FdeStatus::Suspended => write!(f, "Suspended"),
            FdeStatus::Recovery => write!(f, "Recovery"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub drive_letter: String,
    pub encrypted: bool,
    pub algorithm: String,
    pub protection_status: FdeStatus,
    pub escrowed: bool,
    pub encryption_percent: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdeAlert {
    pub id: Uuid,
    pub drive_letter: String,
    pub previous_status: FdeStatus,
    pub current_status: FdeStatus,
    pub severity: EventSeverity,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

pub struct FdeMonitor {
    volumes: HashMap<String, VolumeInfo>,
    alerts: Vec<FdeAlert>,
}

impl FdeMonitor {
    pub fn new() -> Self {
        info!("Initializing FDE monitor");
        Self {
            volumes: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    pub fn check_volume(&self, drive: &str) -> VolumeInfo {
        if let Some(info) = self.volumes.get(drive) {
            return info.clone();
        }
        VolumeInfo {
            drive_letter: drive.to_string(),
            encrypted: false,
            algorithm: "None".to_string(),
            protection_status: FdeStatus::Decrypted,
            escrowed: false,
            encryption_percent: None,
        }
    }

    pub fn track_volume(&mut self, info: VolumeInfo) {
        let drive = info.drive_letter.clone();
        info!(
            drive = %drive,
            status = %info.protection_status,
            "Tracking volume encryption status"
        );
        self.volumes.insert(drive, info);
    }

    pub fn get_volumes(&self) -> Vec<VolumeInfo> {
        self.volumes.values().cloned().collect()
    }

    pub fn is_fully_encrypted(&self) -> bool {
        !self.volumes.is_empty()
            && self
                .volumes
                .values()
                .all(|v| v.protection_status == FdeStatus::Encrypted)
    }

    pub fn alert_on_decryption(&mut self, volume: &VolumeInfo) -> Option<FdeAlert> {
        if volume.protection_status == FdeStatus::Decrypted {
            let alert = FdeAlert {
                id: Uuid::new_v4(),
                drive_letter: volume.drive_letter.clone(),
                previous_status: FdeStatus::Encrypted,
                current_status: FdeStatus::Decrypted,
                severity: EventSeverity::Critical,
                message: format!(
                    "Drive {} is no longer encrypted! Status changed to Decrypted.",
                    volume.drive_letter
                ),
                timestamp: Utc::now(),
            };
            warn!(
                drive = %volume.drive_letter,
                "FDE decryption detected - alert raised"
            );
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        if volume.protection_status == FdeStatus::Suspended {
            let alert = FdeAlert {
                id: Uuid::new_v4(),
                drive_letter: volume.drive_letter.clone(),
                previous_status: FdeStatus::Encrypted,
                current_status: FdeStatus::Suspended,
                severity: EventSeverity::High,
                message: format!(
                    "Drive {} encryption is suspended. BitLocker protection is not active.",
                    volume.drive_letter
                ),
                timestamp: Utc::now(),
            };
            warn!(
                drive = %volume.drive_letter,
                "FDE encryption suspended - alert raised"
            );
            self.alerts.push(alert.clone());
            return Some(alert);
        }

        None
    }

    pub fn alerts(&self) -> &[FdeAlert] {
        &self.alerts
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }
}

impl Default for FdeMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_volume(drive: &str) -> VolumeInfo {
        VolumeInfo {
            drive_letter: drive.to_string(),
            encrypted: true,
            algorithm: "AES-256".to_string(),
            protection_status: FdeStatus::Encrypted,
            escrowed: true,
            encryption_percent: Some(100.0),
        }
    }

    #[test]
    fn test_fde_monitor_new() {
        let monitor = FdeMonitor::new();
        assert!(monitor.volumes.is_empty());
        assert!(monitor.alerts.is_empty());
    }

    #[test]
    fn test_check_volume_returns_default_when_not_tracked() {
        let monitor = FdeMonitor::new();
        let info = monitor.check_volume("C:");
        assert_eq!(info.drive_letter, "C:");
        assert!(!info.encrypted);
        assert_eq!(info.protection_status, FdeStatus::Decrypted);
    }

    #[test]
    fn test_track_volume_and_check() {
        let mut monitor = FdeMonitor::new();
        let vol = encrypted_volume("C:");
        monitor.track_volume(vol.clone());
        let info = monitor.check_volume("C:");
        assert!(info.encrypted);
        assert_eq!(info.protection_status, FdeStatus::Encrypted);
        assert_eq!(info.algorithm, "AES-256");
    }

    #[test]
    fn test_get_volumes() {
        let mut monitor = FdeMonitor::new();
        monitor.track_volume(encrypted_volume("C:"));
        monitor.track_volume(encrypted_volume("D:"));
        let volumes = monitor.get_volumes();
        assert_eq!(volumes.len(), 2);
    }

    #[test]
    fn test_is_fully_encrypted_true() {
        let mut monitor = FdeMonitor::new();
        monitor.track_volume(encrypted_volume("C:"));
        monitor.track_volume(encrypted_volume("D:"));
        assert!(monitor.is_fully_encrypted());
    }

    #[test]
    fn test_is_fully_encrypted_false_when_empty() {
        let monitor = FdeMonitor::new();
        assert!(!monitor.is_fully_encrypted());
    }

    #[test]
    fn test_is_fully_encrypted_false_when_partial() {
        let mut monitor = FdeMonitor::new();
        monitor.track_volume(encrypted_volume("C:"));
        monitor.track_volume(VolumeInfo {
            drive_letter: "D:".to_string(),
            encrypted: false,
            algorithm: "None".to_string(),
            protection_status: FdeStatus::Decrypted,
            escrowed: false,
            encryption_percent: None,
        });
        assert!(!monitor.is_fully_encrypted());
    }

    #[test]
    fn test_alert_on_decryption() {
        let mut monitor = FdeMonitor::new();
        let vol = VolumeInfo {
            drive_letter: "C:".to_string(),
            encrypted: false,
            algorithm: "AES-256".to_string(),
            protection_status: FdeStatus::Decrypted,
            escrowed: false,
            encryption_percent: None,
        };
        let alert = monitor.alert_on_decryption(&vol);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, EventSeverity::Critical);
        assert_eq!(alert.drive_letter, "C:");
        assert_eq!(monitor.alert_count(), 1);
    }

    #[test]
    fn test_alert_on_suspension() {
        let mut monitor = FdeMonitor::new();
        let vol = VolumeInfo {
            drive_letter: "D:".to_string(),
            encrypted: true,
            algorithm: "AES-256".to_string(),
            protection_status: FdeStatus::Suspended,
            escrowed: true,
            encryption_percent: Some(100.0),
        };
        let alert = monitor.alert_on_decryption(&vol);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, EventSeverity::High);
    }

    #[test]
    fn test_no_alert_when_encrypted() {
        let mut monitor = FdeMonitor::new();
        let vol = encrypted_volume("C:");
        let alert = monitor.alert_on_decryption(&vol);
        assert!(alert.is_none());
        assert_eq!(monitor.alert_count(), 0);
    }

    #[test]
    fn test_default_trait() {
        let monitor = FdeMonitor::default();
        assert!(monitor.volumes.is_empty());
    }

    #[test]
    fn test_fde_status_display() {
        assert_eq!(FdeStatus::Encrypted.to_string(), "Encrypted");
        assert_eq!(FdeStatus::Encrypting.to_string(), "Encrypting");
        assert_eq!(FdeStatus::Suspended.to_string(), "Suspended");
    }
}
