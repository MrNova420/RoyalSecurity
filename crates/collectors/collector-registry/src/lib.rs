pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc, TimeDelta};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryChange {
    pub key_path: String,
    pub value_name: String,
    pub value_data: Option<String>,
    pub action: RegistryAction,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid registry change: {0}")]
    InvalidChange(String),
}

pub struct RegistryCollector {
    running: Arc<RwLock<bool>>,
    changes: Arc<RwLock<Vec<RegistryChange>>>,
}

impl RegistryCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            changes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self)  -> std::result::Result<(), RegistryCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("Registry collector started");
        Ok(())
    }

    pub async fn stop(&self)  -> std::result::Result<(), RegistryCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("Registry collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_change(&self, event: RegistryChange)  -> std::result::Result<(), RegistryCollectorError> {
        if !*self.running.read().await {
            return Err(RegistryCollectorError::NotStarted.into());
        }
        if event.key_path.is_empty() {
            return Err(RegistryCollectorError::InvalidChange(
                "Empty key path".into(),
            )
            .into());
        }
        debug!(
            key = %event.key_path,
            action = %event.action,
            pid = event.pid,
            "Captured registry change"
        );
        let mut changes = self.changes.write().await;
        changes.push(event);
        Ok(())
    }

    pub async fn get_changes(&self) -> Vec<RegistryChange> {
        self.changes.read().await.clone()
    }

    pub async fn get_changes_by_key(&self, key: &str) -> Vec<RegistryChange> {
        self.changes
            .read()
            .await
            .iter()
            .filter(|c| c.key_path.contains(key))
            .cloned()
            .collect()
    }

    pub async fn change_count(&self) -> usize {
        self.changes.read().await.len()
    }

    pub async fn purge_old(&self, max_age_secs: u64) {
        let cutoff = Utc::now() - TimeDelta::seconds(max_age_secs as i64);
        let mut changes = self.changes.write().await;
        let before = changes.len();
        changes.retain(|c| c.timestamp > cutoff);
        let purged = before - changes.len();
        if purged > 0 {
            debug!("Purged {} old registry changes", purged);
        }
    }

    pub async fn clear(&self) {
        self.changes.write().await.clear();
        debug!("Registry collector cleared all changes");
    }
}

impl Default for RegistryCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_change(key: &str, action: RegistryAction) -> RegistryChange {
        RegistryChange {
            key_path: key.to_string(),
            value_name: "TestValue".to_string(),
            value_data: Some("TestData".to_string()),
            action,
            process_name: "test.exe".to_string(),
            pid: 1234,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_new_collector_is_not_running() {
        let collector = RegistryCollector::new();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = RegistryCollector::new();
        let event = make_change("HKLM\\Software\\Test", RegistryAction::Created);
        assert!(collector.capture_change(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_change() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        let event = make_change("HKLM\\Software\\Test", RegistryAction::Created);
        collector.capture_change(event).await.unwrap();
        assert_eq!(collector.change_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_key() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        let event = make_change("", RegistryAction::Created);
        assert!(collector.capture_change(event).await.is_err());
    }

    #[tokio::test]
    async fn test_get_changes_by_key() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_change(make_change("HKLM\\Software\\Microsoft", RegistryAction::Created))
            .await
            .unwrap();
        collector
            .capture_change(make_change("HKLM\\Software\\Test", RegistryAction::Modified))
            .await
            .unwrap();
        collector
            .capture_change(make_change("HKCU\\Environment", RegistryAction::Deleted))
            .await
            .unwrap();

        let ms_changes = collector.get_changes_by_key("Microsoft").await;
        assert_eq!(ms_changes.len(), 1);

        let all_hklm = collector.get_changes_by_key("HKLM").await;
        assert_eq!(all_hklm.len(), 2);
    }

    #[tokio::test]
    async fn test_purge_old() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        let mut old_event = make_change("HKLM\\Old", RegistryAction::Created);
        old_event.timestamp = Utc::now() - TimeDelta::seconds(3600);
        collector.capture_change(old_event).await.unwrap();
        collector
            .capture_change(make_change("HKLM\\New", RegistryAction::Created))
            .await
            .unwrap();
        assert_eq!(collector.change_count().await, 2);

        collector.purge_old(60).await;
        assert_eq!(collector.change_count().await, 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_change(make_change("HKLM\\Test", RegistryAction::Created))
            .await
            .unwrap();
        assert_eq!(collector.change_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.change_count().await, 0);
    }
}

