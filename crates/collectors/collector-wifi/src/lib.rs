pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WifiEventType {
    Connected,
    Disconnected,
    Roamed,
    NetworkChanged,
    DeauthReceived,
    ProbeRequest,
}

impl std::fmt::Display for WifiEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WifiEventType::Connected => write!(f, "Connected"),
            WifiEventType::Disconnected => write!(f, "Disconnected"),
            WifiEventType::Roamed => write!(f, "Roamed"),
            WifiEventType::NetworkChanged => write!(f, "NetworkChanged"),
            WifiEventType::DeauthReceived => write!(f, "DeauthReceived"),
            WifiEventType::ProbeRequest => write!(f, "ProbeRequest"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnection {
    pub ssid: String,
    pub bssid: String,
    pub security_type: String,
    pub signal_dbm: i32,
    pub frequency: u32,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiEvent {
    pub event_type: WifiEventType,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum WifiCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid WiFi event: {0}")]
    InvalidEvent(String),
}

pub struct WifiCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<WifiEvent>>>,
    current_connection: Arc<RwLock<Option<WifiConnection>>>,
}

impl WifiCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            current_connection: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), WifiCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("WiFi collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), WifiCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("WiFi collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn set_current_connection(&self, conn: Option<WifiConnection>) {
        let mut current = self.current_connection.write().await;
        *current = conn;
    }

    pub async fn get_current_connection(&self) -> Option<WifiConnection> {
        self.current_connection.read().await.clone()
    }

    pub async fn capture_event(&self, event: WifiEvent) -> std::result::Result<(), WifiCollectorError> {
        if !*self.running.read().await {
            return Err(WifiCollectorError::NotStarted.into());
        }
        debug!(
            event_type = %event.event_type,
            details = %event.details,
            "Captured WiFi event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    pub async fn get_events(&self) -> Vec<WifiEvent> {
        self.events.read().await.clone()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        *self.current_connection.write().await = None;
        debug!("WiFi collector cleared all events");
    }
}

impl Default for WifiCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: WifiEventType, details: &str) -> WifiEvent {
        WifiEvent {
            event_type,
            details: details.to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_connection(ssid: &str) -> WifiConnection {
        WifiConnection {
            ssid: ssid.to_string(),
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            security_type: "WPA2".to_string(),
            signal_dbm: -45,
            frequency: 5240,
            connected_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = WifiCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = WifiCollector::new();
        let event = make_event(WifiEventType::Connected, "Connected to MyWiFi");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = WifiCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WifiEventType::Connected, "Connected to MyWiFi");
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_current_connection() {
        let collector = WifiCollector::new();
        assert!(collector.get_current_connection().await.is_none());
        let conn = make_connection("MyWiFi");
        collector.set_current_connection(Some(conn.clone())).await;
        let current = collector.get_current_connection().await.unwrap();
        assert_eq!(current.ssid, "MyWiFi");
        assert_eq!(current.signal_dbm, -45);
    }

    #[tokio::test]
    async fn test_clear_connection() {
        let collector = WifiCollector::new();
        collector
            .set_current_connection(Some(make_connection("Test")))
            .await;
        assert!(collector.get_current_connection().await.is_some());
        collector.clear().await;
        assert!(collector.get_current_connection().await.is_none());
    }

    #[tokio::test]
    async fn test_all_event_types() {
        let collector = WifiCollector::new();
        collector.start().await.unwrap();
        let types = [
            WifiEventType::Connected,
            WifiEventType::Disconnected,
            WifiEventType::Roamed,
            WifiEventType::NetworkChanged,
            WifiEventType::DeauthReceived,
            WifiEventType::ProbeRequest,
        ];
        for (i, et) in types.iter().enumerate() {
            collector
                .capture_event(make_event(*et, &format!("event{}", i)))
                .await
                .unwrap();
        }
        assert_eq!(collector.event_count().await, 6);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = WifiCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WifiEventType::Connected, "test"))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }
}
