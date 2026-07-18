pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, ProcessInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshot {
    pub id: String,
    pub creation_time: DateTime<Utc>,
    pub volume: String,
    pub size: u64,
    pub creator: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VssAlertType {
    SnapshotDeleted,
    SnapshotCreated,
    RollbackAttempt,
    SuspiciousAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssAlert {
    pub alert_type: VssAlertType,
    pub snapshot_id: String,
    pub process_name: Option<String>,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssEvent {
    pub snapshot_id: String,
    pub event_type: VssAlertType,
    pub process_name: String,
    pub timestamp: DateTime<Utc>,
}

pub struct VssGuard {
    snapshots: HashMap<String, VssSnapshot>,
    alert_count: u64,
}

impl VssGuard {
    pub fn new() -> Self {
        info!("Initializing VSS Guard");
        Self {
            snapshots: HashMap::new(),
            alert_count: 0,
        }
    }

    pub fn track_snapshot(&mut self, snap: VssSnapshot) {
        info!(id = %snap.id, volume = %snap.volume, "Tracking VSS snapshot");
        self.snapshots.insert(snap.id.clone(), snap);
    }

    pub fn detect_deletion(
        &mut self,
        snapshot_id: &str,
        process: &ProcessInfo,
    ) -> Option<VssAlert> {
        let _snapshot = match self.snapshots.remove(snapshot_id) {
            Some(s) => s,
            None => return None,
        };

        let is_suspicious = process.name.to_lowercase().contains("vssadmin")
            || process.name.to_lowercase().contains("wmic")
            || process.name.to_lowercase().contains("bcdedit")
            || process.command_line.to_lowercase().contains("delete shadows");

        let (severity, msg) = if is_suspicious {
            (
                EventSeverity::Critical,
                format!(
                    "Suspicious shadow copy deletion by {} (pid: {}): {}",
                    process.name, process.pid, process.command_line
                ),
            )
        } else {
            (
                EventSeverity::Medium,
                format!(
                    "Shadow copy {} deleted by {}",
                    snapshot_id, process.name
                ),
            )
        };

        self.alert_count += 1;
        warn!(
            snapshot_id = snapshot_id,
            process = %process.name,
            "Shadow copy deletion detected"
        );

        Some(VssAlert {
            alert_type: VssAlertType::SnapshotDeleted,
            snapshot_id: snapshot_id.to_string(),
            process_name: Some(process.name.clone()),
            message: msg,
            severity,
            timestamp: Utc::now(),
        })
    }

    pub fn get_snapshots(&self) -> Vec<&VssSnapshot> {
        self.snapshots.values().collect()
    }

    pub fn detect_mass_deletion(&mut self, events: &[VssEvent]) -> Option<VssAlert> {
        let deletions: Vec<&VssEvent> = events
            .iter()
            .filter(|e| e.event_type == VssAlertType::SnapshotDeleted)
            .collect();

        if deletions.len() >= 3 {
            self.alert_count += 1;
            warn!(
                count = deletions.len(),
                "Mass shadow copy deletion detected (ransomware indicator)"
            );

            Some(VssAlert {
                alert_type: VssAlertType::SnapshotDeleted,
                snapshot_id: "batch".to_string(),
                process_name: Some(deletions[0].process_name.clone()),
                message: format!(
                    "Mass shadow copy deletion detected: {} snapshots deleted in rapid succession",
                    deletions.len()
                ),
                severity: EventSeverity::Critical,
                timestamp: Utc::now(),
            })
        } else {
            None
        }
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }
}

impl Default for VssGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::ProcessInfo;

    fn make_snapshot(id: &str) -> VssSnapshot {
        VssSnapshot {
            id: id.to_string(),
            creation_time: Utc::now(),
            volume: "C:\\".to_string(),
            size: 1024 * 1024 * 100,
            creator: "System".to_string(),
        }
    }

    fn make_process(name: &str, cmd: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: name.to_string(),
            path: format!("C:\\Windows\\System32\\{}", name),
            command_line: cmd.to_string(),
            user: "SYSTEM".to_string(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_vss_guard_new() {
        let guard = VssGuard::new();
        assert_eq!(guard.alert_count(), 0);
        assert!(guard.get_snapshots().is_empty());
    }

    #[test]
    fn test_track_snapshot() {
        let mut guard = VssGuard::new();
        guard.track_snapshot(make_snapshot("snap-1"));
        guard.track_snapshot(make_snapshot("snap-2"));
        assert_eq!(guard.get_snapshots().len(), 2);
    }

    #[test]
    fn test_detect_deletion_suspicious() {
        let mut guard = VssGuard::new();
        guard.track_snapshot(make_snapshot("snap-1"));

        let process = make_process("vssadmin.exe", "vssadmin delete shadows /all");
        let alert = guard.detect_deletion("snap-1", &process);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.alert_type, VssAlertType::SnapshotDeleted);
        assert_eq!(alert.severity, EventSeverity::Critical);
        assert_eq!(guard.alert_count(), 1);
    }

    #[test]
    fn test_detect_deletion_normal() {
        let mut guard = VssGuard::new();
        guard.track_snapshot(make_snapshot("snap-2"));

        let process = make_process("svchost.exe", "");
        let alert = guard.detect_deletion("snap-2", &process);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, EventSeverity::Medium);
    }

    #[test]
    fn test_detect_deletion_nonexistent() {
        let mut guard = VssGuard::new();
        let process = make_process("cmd.exe", "");
        let alert = guard.detect_deletion("nonexistent", &process);
        assert!(alert.is_none());
    }

    #[test]
    fn test_detect_mass_deletion() {
        let mut guard = VssGuard::new();
        let events: Vec<VssEvent> = (0..5)
            .map(|i| VssEvent {
                snapshot_id: format!("snap-{}", i),
                event_type: VssAlertType::SnapshotDeleted,
                process_name: "vssadmin.exe".to_string(),
                timestamp: Utc::now(),
            })
            .collect();

        let alert = guard.detect_mass_deletion(&events);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, EventSeverity::Critical);
        assert!(alert.message.contains("5 snapshots"));
        assert_eq!(guard.alert_count(), 1);
    }

    #[test]
    fn test_mass_deletion_below_threshold() {
        let mut guard = VssGuard::new();
        let events: Vec<VssEvent> = (0..2)
            .map(|i| VssEvent {
                snapshot_id: format!("snap-{}", i),
                event_type: VssAlertType::SnapshotDeleted,
                process_name: "vssadmin.exe".to_string(),
                timestamp: Utc::now(),
            })
            .collect();

        let alert = guard.detect_mass_deletion(&events);
        assert!(alert.is_none());
        assert_eq!(guard.alert_count(), 0);
    }

    #[test]
    fn test_get_snapshots_after_deletion() {
        let mut guard = VssGuard::new();
        guard.track_snapshot(make_snapshot("snap-1"));
        guard.track_snapshot(make_snapshot("snap-2"));
        assert_eq!(guard.get_snapshots().len(), 2);

        let process = make_process("vssadmin.exe", "vssadmin delete shadows");
        guard.detect_deletion("snap-1", &process);
        assert_eq!(guard.get_snapshots().len(), 1);
    }
}
