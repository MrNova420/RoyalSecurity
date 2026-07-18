pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UsbEventType {
    Connected,
    Disconnected,
    DataTransfer,
    UnauthorizedDevice,
}

impl std::fmt::Display for UsbEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbEventType::Connected => write!(f, "Connected"),
            UsbEventType::Disconnected => write!(f, "Disconnected"),
            UsbEventType::DataTransfer => write!(f, "DataTransfer"),
            UsbEventType::UnauthorizedDevice => write!(f, "UnauthorizedDevice"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub id: String,
    pub vendor_id: String,
    pub product_id: String,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub connected: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEvent {
    pub device_id: String,
    pub event_type: UsbEventType,
    pub bytes_transferred: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum UsbCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid USB event: {0}")]
    InvalidEvent(String),
}

pub struct UsbCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<UsbEvent>>>,
    known_devices: Arc<RwLock<Vec<UsbDevice>>>,
}

impl UsbCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            known_devices: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), UsbCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("USB collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), UsbCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("USB collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_event(&self, event: UsbEvent) -> std::result::Result<(), UsbCollectorError> {
        if !*self.running.read().await {
            return Err(UsbCollectorError::NotStarted.into());
        }
        if event.device_id.is_empty() {
            return Err(UsbCollectorError::InvalidEvent(
                "Empty device ID".into(),
            )
            .into());
        }
        debug!(
            device = %event.device_id,
            event_type = %event.event_type,
            bytes = event.bytes_transferred,
            "Captured USB event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    pub async fn add_known_device(&self, device: UsbDevice) {
        let mut devices = self.known_devices.write().await;
        devices.push(device);
    }

    pub async fn is_known(&self, vendor_id: &str, product_id: &str) -> bool {
        self.known_devices
            .read()
            .await
            .iter()
            .any(|d| d.vendor_id == vendor_id && d.product_id == product_id)
    }

    pub async fn get_events(&self) -> Vec<UsbEvent> {
        self.events.read().await.clone()
    }

    pub async fn get_known_devices(&self) -> Vec<UsbDevice> {
        self.known_devices.read().await.clone()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        debug!("USB collector cleared all events");
    }
}

impl Default for UsbCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(device_id: &str, event_type: UsbEventType) -> UsbEvent {
        UsbEvent {
            device_id: device_id.to_string(),
            event_type,
            bytes_transferred: 0,
            timestamp: Utc::now(),
        }
    }

    fn make_device(vendor_id: &str, product_id: &str) -> UsbDevice {
        UsbDevice {
            id: format!("{}:{}", vendor_id, product_id),
            vendor_id: vendor_id.to_string(),
            product_id: product_id.to_string(),
            serial: None,
            manufacturer: None,
            connected: true,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = UsbCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = UsbCollector::new();
        let event = make_event("dev1", UsbEventType::Connected);
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = UsbCollector::new();
        collector.start().await.unwrap();
        let event = make_event("dev1", UsbEventType::Connected);
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_device_id() {
        let collector = UsbCollector::new();
        collector.start().await.unwrap();
        let event = make_event("", UsbEventType::Connected);
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_known_device_lookup() {
        let collector = UsbCollector::new();
        assert!(!collector.is_known("046d", "082d").await);
        collector
            .add_known_device(make_device("046d", "082d"))
            .await;
        assert!(collector.is_known("046d", "082d").await);
        assert!(!collector.is_known("046d", "9999").await);
    }

    #[tokio::test]
    async fn test_unauthorized_detection() {
        let collector = UsbCollector::new();
        collector.start().await.unwrap();
        collector
            .add_known_device(make_device("AAAA", "BBBB"))
            .await;

        let event = UsbEvent {
            device_id: "unknown-dev".into(),
            event_type: UsbEventType::UnauthorizedDevice,
            bytes_transferred: 0,
            timestamp: Utc::now(),
        };
        collector.capture_event(event).await.unwrap();

        let events = collector.get_events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, UsbEventType::UnauthorizedDevice);
    }

    #[tokio::test]
    async fn test_data_transfer_tracking() {
        let collector = UsbCollector::new();
        collector.start().await.unwrap();
        let mut event = make_event("dev1", UsbEventType::DataTransfer);
        event.bytes_transferred = 1024 * 1024;
        collector.capture_event(event).await.unwrap();
        let events = collector.get_events().await;
        assert_eq!(events[0].bytes_transferred, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = UsbCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event("dev1", UsbEventType::Connected))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }
}
