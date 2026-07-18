pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_core::bus::EventBus;
use std::error::Error;
use std::collections::HashMap;
use std::time::Instant;
use tracing::info;
use chrono::{DateTime, Utc};

#[derive(Debug, thiserror::Error)]
pub enum BluetoothError {
    #[error("Bluetooth collector not running")]
    NotRunning,
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BluetoothDevice {
    pub id: String,
    pub name: String,
    pub mac_address: String,
    pub device_class: u32,
    pub paired: bool,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum BluetoothEventType {
    DeviceDiscovered,
    Paired,
    Unpaired,
    Connected,
    Disconnected,
    SuspiciousActivity,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BluetoothEvent {
    pub device_id: String,
    pub event_type: BluetoothEventType,
    pub timestamp: DateTime<Utc>,
}

pub struct BluetoothCollector {
    _bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    devices: HashMap<String, BluetoothDevice>,
    events: Vec<BluetoothEvent>,
    known_devices: Vec<String>,
}

impl BluetoothCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            devices: HashMap::new(),
            events: Vec::new(),
            known_devices: Vec::new(),
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), BluetoothError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!(
            "Bluetooth Collector started with {} devices",
            self.devices.len()
        );
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), BluetoothError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Bluetooth Collector stopped. Processed {} events",
            self.events_processed
        );
        Ok(())
    }

    pub fn collect_events(&mut self) -> Vec<BluetoothEvent> {
        let events: Vec<BluetoothEvent> = self.events.drain(..).collect();
        self.events_processed += events.len() as u64;
        events
    }

    pub fn add_known_device(&mut self, device: BluetoothDevice) {
        let event = BluetoothEvent {
            device_id: device.id.clone(),
            event_type: BluetoothEventType::DeviceDiscovered,
            timestamp: Utc::now(),
        };
        self.known_devices.push(device.mac_address.clone());
        self.devices.insert(device.id.clone(), device);
        self.events.push(event);
    }

    pub fn is_known(&self, mac: &str) -> bool {
        self.known_devices.iter().any(|k| k == mac)
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn pair_device(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), BluetoothError> {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.paired = true;
            let event = BluetoothEvent {
                device_id: device_id.to_string(),
                event_type: BluetoothEventType::Paired,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(BluetoothError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn unpair_device(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), BluetoothError> {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.paired = false;
            let event = BluetoothEvent {
                device_id: device_id.to_string(),
                event_type: BluetoothEventType::Unpaired,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(BluetoothError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn connect_device(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), BluetoothError> {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.last_seen = Utc::now();
            let event = BluetoothEvent {
                device_id: device_id.to_string(),
                event_type: BluetoothEventType::Connected,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(BluetoothError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn disconnect_device(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), BluetoothError> {
        if self.devices.contains_key(device_id) {
            let event = BluetoothEvent {
                device_id: device_id.to_string(),
                event_type: BluetoothEventType::Disconnected,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(BluetoothError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn report_suspicious(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), BluetoothError> {
        if self.devices.contains_key(device_id) {
            let event = BluetoothEvent {
                device_id: device_id.to_string(),
                event_type: BluetoothEventType::SuspiciousActivity,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(BluetoothError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn get_device(&self, device_id: &str) -> Option<&BluetoothDevice> {
        self.devices.get(device_id)
    }

    pub fn get_devices(&self) -> Vec<&BluetoothDevice> {
        self.devices.values().collect()
    }

    pub fn remove_device(&mut self, device_id: &str) -> bool {
        self.devices.remove(device_id).is_some()
    }
}

#[async_trait]
impl SecurityModule for BluetoothCollector {
    fn name(&self) -> &str {
        "Bluetooth Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors Bluetooth devices, connections, and pairing activity"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Bluetooth Collector initialized");
        Ok(())
    }

    async fn start(&mut self) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.start()?;
        Ok(())
    }

    async fn stop(&mut self) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.stop()?;
        Ok(())
    }

    async fn health(&self) -> ModuleHealth {
        ModuleHealth {
            status: self.status.clone(),
            last_heartbeat: Utc::now(),
            error_count: self.errors,
            events_processed: self.events_processed,
            events_per_second: 0.0,
            memory_usage_bytes: 0,
        }
    }

    async fn handle_event(&self, _event: &SecurityEvent) -> Option<SecurityEvent> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bus() -> EventBus {
        EventBus::new()
    }

    fn test_device(id: &str, mac: &str) -> BluetoothDevice {
        BluetoothDevice {
            id: id.into(),
            name: format!("Device {}", id),
            mac_address: mac.into(),
            device_class: 0x240404,
            paired: false,
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn test_new_collector() {
        let collector = BluetoothCollector::new(test_bus());
        assert_eq!(collector.device_count(), 0);
    }

    #[test]
    fn test_add_known_device_and_is_known() {
        let mut collector = BluetoothCollector::new(test_bus());
        let device = test_device("bt1", "AA:BB:CC:DD:EE:FF");
        collector.add_known_device(device);
        assert_eq!(collector.device_count(), 1);
        assert!(collector.is_known("AA:BB:CC:DD:EE:FF"));
        assert!(!collector.is_known("11:22:33:44:55:66"));
    }

    #[test]
    fn test_pair_unpair_device() {
        let mut collector = BluetoothCollector::new(test_bus());
        let device = test_device("bt1", "AA:BB:CC:DD:EE:FF");
        collector.add_known_device(device);
        assert!(collector.pair_device("bt1").is_ok());
        assert!(collector.get_device("bt1").unwrap().paired);
        assert!(collector.unpair_device("bt1").is_ok());
        assert!(!collector.get_device("bt1").unwrap().paired);
        assert!(collector.pair_device("nonexistent").is_err());
    }

    #[test]
    fn test_connect_disconnect_device() {
        let mut collector = BluetoothCollector::new(test_bus());
        let device = test_device("bt1", "AA:BB:CC:DD:EE:FF");
        collector.add_known_device(device);
        assert!(collector.connect_device("bt1").is_ok());
        assert!(collector.disconnect_device("bt1").is_ok());
        assert!(collector.connect_device("nonexistent").is_err());
    }

    #[test]
    fn test_collect_events() {
        let mut collector = BluetoothCollector::new(test_bus());
        let device = test_device("bt1", "AA:BB:CC:DD:EE:FF");
        collector.add_known_device(device);
        let _ = collector.pair_device("bt1");
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, BluetoothEventType::DeviceDiscovered);
        assert_eq!(events[1].event_type, BluetoothEventType::Paired);
        assert!(collector.collect_events().is_empty());
    }

    #[test]
    fn test_suspicious_activity() {
        let mut collector = BluetoothCollector::new(test_bus());
        let device = test_device("bt1", "AA:BB:CC:DD:EE:FF");
        collector.add_known_device(device);
        assert!(collector.report_suspicious("bt1").is_ok());
        assert!(collector.report_suspicious("nonexistent").is_err());
        let events = collector.collect_events();
        assert_eq!(events[1].event_type, BluetoothEventType::SuspiciousActivity);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = BluetoothCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.stop().is_ok());
    }

    #[test]
    fn test_remove_device() {
        let mut collector = BluetoothCollector::new(test_bus());
        let device = test_device("bt1", "AA:BB:CC:DD:EE:FF");
        collector.add_known_device(device);
        assert!(collector.remove_device("bt1"));
        assert_eq!(collector.device_count(), 0);
        assert!(!collector.remove_device("nonexistent"));
    }

    #[test]
    fn test_multiple_devices() {
        let mut collector = BluetoothCollector::new(test_bus());
        collector.add_known_device(test_device("bt1", "AA:BB:CC:DD:EE:01"));
        collector.add_known_device(test_device("bt2", "AA:BB:CC:DD:EE:02"));
        collector.add_known_device(test_device("bt3", "AA:BB:CC:DD:EE:03"));
        assert_eq!(collector.device_count(), 3);
        assert!(collector.is_known("AA:BB:CC:DD:EE:01"));
        assert!(collector.is_known("AA:BB:CC:DD:EE:03"));
    }
}
