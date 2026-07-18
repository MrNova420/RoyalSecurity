pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UsnReason {
    DataOverwrite,
    DataExtend,
    DataTruncation,
    NamedDataOverwrite,
    NamedDataExtend,
    FileCreate,
    FileDelete,
    EaChange,
    SecurityChange,
    RenameOldName,
    RenameNewName,
}

impl std::fmt::Display for UsnReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsnReason::DataOverwrite => write!(f, "DataOverwrite"),
            UsnReason::DataExtend => write!(f, "DataExtend"),
            UsnReason::DataTruncation => write!(f, "DataTruncation"),
            UsnReason::NamedDataOverwrite => write!(f, "NamedDataOverwrite"),
            UsnReason::NamedDataExtend => write!(f, "NamedDataExtend"),
            UsnReason::FileCreate => write!(f, "FileCreate"),
            UsnReason::FileDelete => write!(f, "FileDelete"),
            UsnReason::EaChange => write!(f, "EaChange"),
            UsnReason::SecurityChange => write!(f, "SecurityChange"),
            UsnReason::RenameOldName => write!(f, "RenameOldName"),
            UsnReason::RenameNewName => write!(f, "RenameNewName"),
        }
    }
}

impl UsnReason {
    pub fn from_usn_code(code: u32) -> Option<Self> {
        match code {
            0x00000001 => Some(UsnReason::DataOverwrite),
            0x00000002 => Some(UsnReason::DataExtend),
            0x00000004 => Some(UsnReason::DataTruncation),
            0x00000010 => Some(UsnReason::NamedDataOverwrite),
            0x00000020 => Some(UsnReason::NamedDataExtend),
            0x00000100 => Some(UsnReason::FileCreate),
            0x00000200 => Some(UsnReason::FileDelete),
            0x00000400 => Some(UsnReason::EaChange),
            0x00000800 => Some(UsnReason::SecurityChange),
            0x00008000 => Some(UsnReason::RenameOldName),
            0x00010000 => Some(UsnReason::RenameNewName),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnEntry {
    pub file_ref_number: u64,
    pub parent_ref: u64,
    pub usn: i64,
    pub reason: UsnReason,
    pub file_name: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum UsnCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid USN entry: {0}")]
    InvalidEntry(String),
}

pub struct UsnCollector {
    running: Arc<RwLock<bool>>,
    entries: Arc<RwLock<Vec<UsnEntry>>>,
}

impl UsnCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self)  -> std::result::Result<(), UsnCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("USN journal collector started");
        Ok(())
    }

    pub async fn stop(&self)  -> std::result::Result<(), UsnCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("USN journal collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_entry(&self, entry: UsnEntry)  -> std::result::Result<(), UsnCollectorError> {
        if !*self.running.read().await {
            return Err(UsnCollectorError::NotStarted.into());
        }
        if entry.file_name.is_empty() {
            return Err(UsnCollectorError::InvalidEntry(
                "Empty file name".into(),
            )
            .into());
        }
        debug!(
            file = %entry.file_name,
            reason = %entry.reason,
            usn = entry.usn,
            "Captured USN journal entry"
        );
        let mut entries = self.entries.write().await;
        entries.push(entry);
        Ok(())
    }

    pub async fn get_entries(&self) -> Vec<UsnEntry> {
        self.entries.read().await.clone()
    }

    pub async fn get_entries_by_reason(&self, reason: UsnReason) -> Vec<UsnEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.reason == reason)
            .cloned()
            .collect()
    }

    pub async fn entry_count(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
        debug!("USN journal collector cleared all entries");
    }
}

impl Default for UsnCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(file_name: &str, reason: UsnReason, usn: i64) -> UsnEntry {
        UsnEntry {
            file_ref_number: 12345,
            parent_ref: 54321,
            usn,
            reason,
            file_name: file_name.to_string(),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = UsnCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = UsnCollector::new();
        let entry = make_entry("test.txt", UsnReason::FileCreate, 100);
        assert!(collector.capture_entry(entry).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_entry() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_entry(make_entry("test.txt", UsnReason::FileCreate, 100))
            .await
            .unwrap();
        assert_eq!(collector.entry_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_filename() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        let entry = make_entry("", UsnReason::FileCreate, 100);
        assert!(collector.capture_entry(entry).await.is_err());
    }

    #[tokio::test]
    async fn test_get_entries_by_reason() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_entry(make_entry("a.txt", UsnReason::FileCreate, 1))
            .await
            .unwrap();
        collector
            .capture_entry(make_entry("b.txt", UsnReason::FileDelete, 2))
            .await
            .unwrap();
        collector
            .capture_entry(make_entry("c.txt", UsnReason::FileCreate, 3))
            .await
            .unwrap();

        let creates = collector.get_entries_by_reason(UsnReason::FileCreate).await;
        assert_eq!(creates.len(), 2);
        let deletes = collector.get_entries_by_reason(UsnReason::FileDelete).await;
        assert_eq!(deletes.len(), 1);
    }

    #[tokio::test]
    async fn test_usn_reason_from_code() {
        assert_eq!(
            UsnReason::from_usn_code(0x00000100),
            Some(UsnReason::FileCreate)
        );
        assert_eq!(
            UsnReason::from_usn_code(0x00000200),
            Some(UsnReason::FileDelete)
        );
        assert_eq!(
            UsnReason::from_usn_code(0x00000001),
            Some(UsnReason::DataOverwrite)
        );
        assert!(UsnReason::from_usn_code(0xFFFFFFFF).is_none());
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_entry(make_entry("test.txt", UsnReason::FileCreate, 100))
            .await
            .unwrap();
        assert_eq!(collector.entry_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.entry_count().await, 0);
    }

    #[tokio::test]
    async fn test_multiple_reasons() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        let reasons = [
            UsnReason::DataOverwrite,
            UsnReason::DataExtend,
            UsnReason::SecurityChange,
            UsnReason::RenameOldName,
            UsnReason::EaChange,
        ];
        for (i, reason) in reasons.iter().enumerate() {
            collector
                .capture_entry(make_entry(&format!("file{}", i), *reason, i as i64))
                .await
                .unwrap();
        }
        assert_eq!(collector.entry_count().await, 5);
    }
}

