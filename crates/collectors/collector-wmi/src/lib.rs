pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WmiOperation {
    Query,
    SubscriptionCreated,
    SubscriptionDeleted,
    MethodCall,
    InstanceCreation,
    InstanceDeletion,
}

impl std::fmt::Display for WmiOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WmiOperation::Query => write!(f, "Query"),
            WmiOperation::SubscriptionCreated => write!(f, "SubscriptionCreated"),
            WmiOperation::SubscriptionDeleted => write!(f, "SubscriptionDeleted"),
            WmiOperation::MethodCall => write!(f, "MethodCall"),
            WmiOperation::InstanceCreation => write!(f, "InstanceCreation"),
            WmiOperation::InstanceDeletion => write!(f, "InstanceDeletion"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiEvent {
    pub namespace: String,
    pub class: String,
    pub operation: WmiOperation,
    pub query: String,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum WmiCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid WMI event: {0}")]
    InvalidEvent(String),
}

pub struct WmiCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<WmiEvent>>>,
}

impl WmiCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), WmiCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("WMI collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), WmiCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("WMI collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_event(&self, event: WmiEvent) -> std::result::Result<(), WmiCollectorError> {
        if !*self.running.read().await {
            return Err(WmiCollectorError::NotStarted.into());
        }
        if event.namespace.is_empty() {
            return Err(WmiCollectorError::InvalidEvent(
                "Empty namespace".into(),
            )
            .into());
        }
        debug!(
            namespace = %event.namespace,
            class = %event.class,
            operation = %event.operation,
            pid = event.pid,
            "Captured WMI event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    pub async fn get_events(&self) -> Vec<WmiEvent> {
        self.events.read().await.clone()
    }

    pub async fn get_events_by_operation(&self, op: WmiOperation) -> Vec<WmiEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.operation == op)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_namespace(&self, namespace: &str) -> Vec<WmiEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.namespace == namespace)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_process(&self, pid: u32) -> Vec<WmiEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.pid == pid)
            .cloned()
            .collect()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        debug!("WMI collector cleared all events");
    }
}

impl Default for WmiCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(operation: WmiOperation, namespace: &str, process: &str) -> WmiEvent {
        WmiEvent {
            namespace: namespace.to_string(),
            class: "Win32_Process".to_string(),
            operation,
            query: "SELECT * FROM Win32_Process".to_string(),
            process_name: process.to_string(),
            pid: 7890,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = WmiCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = WmiCollector::new();
        let event = make_event(WmiOperation::Query, "root\\cimv2", "wmiprvse.exe");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = WmiCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WmiOperation::Query, "root\\cimv2", "wmiprvse.exe");
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_namespace() {
        let collector = WmiCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WmiOperation::Query, "", "wmiprvse.exe");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_get_events_by_operation() {
        let collector = WmiCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WmiOperation::Query, "ns1", "p1.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WmiOperation::SubscriptionCreated, "ns1", "p2.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WmiOperation::Query, "ns2", "p3.exe"))
            .await
            .unwrap();

        let queries = collector
            .get_events_by_operation(WmiOperation::Query)
            .await;
        assert_eq!(queries.len(), 2);
        let subs = collector
            .get_events_by_operation(WmiOperation::SubscriptionCreated)
            .await;
        assert_eq!(subs.len(), 1);
    }

    #[tokio::test]
    async fn test_get_events_by_process() {
        let collector = WmiCollector::new();
        collector.start().await.unwrap();
        let mut evt1 = make_event(WmiOperation::Query, "root\\cimv2", "p1.exe");
        evt1.pid = 100;
        collector.capture_event(evt1).await.unwrap();
        let mut evt2 = make_event(WmiOperation::Query, "root\\cimv2", "p2.exe");
        evt2.pid = 200;
        collector.capture_event(evt2).await.unwrap();
        let mut evt3 = make_event(WmiOperation::Query, "root\\cimv2", "p1.exe");
        evt3.pid = 100;
        collector.capture_event(evt3).await.unwrap();

        let p100 = collector.get_events_by_process(100).await;
        assert_eq!(p100.len(), 2);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = WmiCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WmiOperation::Query, "root\\cimv2", "test.exe"))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }

    #[tokio::test]
    async fn test_all_operations() {
        let collector = WmiCollector::new();
        collector.start().await.unwrap();
        let ops = [
            WmiOperation::Query,
            WmiOperation::SubscriptionCreated,
            WmiOperation::SubscriptionDeleted,
            WmiOperation::MethodCall,
            WmiOperation::InstanceCreation,
            WmiOperation::InstanceDeletion,
        ];
        for (i, op) in ops.iter().enumerate() {
            collector
                .capture_event(make_event(*op, "root\\cimv2", &format!("p{}.exe", i)))
                .await
                .unwrap();
        }
        assert_eq!(collector.event_count().await, 6);
    }
}
