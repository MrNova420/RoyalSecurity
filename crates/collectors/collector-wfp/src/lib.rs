pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WfpAction {
    Permit,
    Block,
    Callout,
    Continue,
    Drop,
}

impl std::fmt::Display for WfpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfpAction::Permit => write!(f, "Permit"),
            WfpAction::Block => write!(f, "Block"),
            WfpAction::Callout => write!(f, "Callout"),
            WfpAction::Continue => write!(f, "Continue"),
            WfpAction::Drop => write!(f, "Drop"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WfpDirection {
    Inbound,
    Outbound,
}

impl std::fmt::Display for WfpDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfpDirection::Inbound => write!(f, "Inbound"),
            WfpDirection::Outbound => write!(f, "Outbound"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpEvent {
    pub filter_id: u32,
    pub action: WfpAction,
    pub direction: WfpDirection,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum WfpCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid WFP event: {0}")]
    InvalidEvent(String),
}

pub struct WfpCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<WfpEvent>>>,
}

impl WfpCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), WfpCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("WFP collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), WfpCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("WFP collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_event(&self, event: WfpEvent) -> std::result::Result<(), WfpCollectorError> {
        if !*self.running.read().await {
            return Err(WfpCollectorError::NotStarted.into());
        }
        if event.process_name.is_empty() {
            return Err(WfpCollectorError::InvalidEvent(
                "Empty process name".into(),
            )
            .into());
        }
        debug!(
            filter_id = event.filter_id,
            action = %event.action,
            process = %event.process_name,
            "Captured WFP event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    pub async fn get_events(&self) -> Vec<WfpEvent> {
        self.events.read().await.clone()
    }

    pub async fn get_blocked_events(&self) -> Vec<WfpEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.action == WfpAction::Block || e.action == WfpAction::Drop)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_action(&self, action: WfpAction) -> Vec<WfpEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.action == action)
            .cloned()
            .collect()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        debug!("WFP collector cleared all events");
    }
}

impl Default for WfpCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(action: WfpAction, process: &str) -> WfpEvent {
        WfpEvent {
            filter_id: 100,
            action,
            direction: WfpDirection::Outbound,
            protocol: "TCP".to_string(),
            local_addr: "192.168.1.1".to_string(),
            remote_addr: "10.0.0.1".to_string(),
            local_port: 443,
            remote_port: 8080,
            process_name: process.to_string(),
            pid: 4321,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = WfpCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = WfpCollector::new();
        let event = make_event(WfpAction::Permit, "chrome.exe");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WfpAction::Permit, "chrome.exe");
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_process() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WfpAction::Permit, "");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_get_blocked_events() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WfpAction::Permit, "a.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Block, "b.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Drop, "c.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Permit, "d.exe"))
            .await
            .unwrap();

        let blocked = collector.get_blocked_events().await;
        assert_eq!(blocked.len(), 2);
    }

    #[tokio::test]
    async fn test_get_events_by_action() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WfpAction::Block, "a.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Block, "b.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Callout, "c.exe"))
            .await
            .unwrap();

        let blocks = collector.get_events_by_action(WfpAction::Block).await;
        assert_eq!(blocks.len(), 2);
        let callouts = collector.get_events_by_action(WfpAction::Callout).await;
        assert_eq!(callouts.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WfpAction::Permit, "test.exe"))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }

    #[tokio::test]
    async fn test_direction_tracking() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        let mut inbound = make_event(WfpAction::Permit, "server.exe");
        inbound.direction = WfpDirection::Inbound;
        collector.capture_event(inbound).await.unwrap();
        let events = collector.get_events().await;
        assert_eq!(events[0].direction, WfpDirection::Inbound);
    }
}
