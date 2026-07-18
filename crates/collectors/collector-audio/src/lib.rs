pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_core::bus::EventBus;
use std::error::Error;
use std::time::Instant;
use tracing::info;
use chrono::{DateTime, Utc};

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("Audio collector not running")]
    NotRunning,
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Unauthorized capture detected from process: {0}")]
    UnauthorizedCapture(String),
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudioDevice {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub active: bool,
    pub last_activity: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AudioEventType {
    DeviceConnected,
    DeviceDisconnected,
    RecordingStarted,
    RecordingStopped,
    UnauthorizedCapture,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudioEvent {
    pub device_id: String,
    pub event_type: AudioEventType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudioAlert {
    pub device_id: String,
    pub process_name: String,
    pub pid: u32,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

pub struct AudioCollector {
    _bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    devices: Vec<AudioDevice>,
    events: Vec<AudioEvent>,
    known_unauthorized: Vec<String>,
}

impl AudioCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            devices: Vec::new(),
            events: Vec::new(),
            known_unauthorized: vec![
                "keylogger.exe".into(),
                "spyware.exe".into(),
                "recorder.exe".into(),
            ],
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), AudioError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("Audio Collector started with {} devices", self.devices.len());
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), AudioError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Audio Collector stopped. Processed {} events",
            self.events_processed
        );
        Ok(())
    }

    pub fn collect_events(&mut self) -> Vec<AudioEvent> {
        let events: Vec<AudioEvent> = self.events.drain(..).collect();
        self.events_processed += events.len() as u64;
        events
    }

    pub fn add_device(&mut self, device: AudioDevice) {
        let event = AudioEvent {
            device_id: device.id.clone(),
            event_type: AudioEventType::DeviceConnected,
            timestamp: Utc::now(),
        };
        self.devices.push(device);
        self.events.push(event);
    }

    pub fn remove_device(&mut self, device_id: &str) -> bool {
        let pos = self.devices.iter().position(|d| d.id == device_id);
        if let Some(idx) = pos {
            self.devices.remove(idx);
            let event = AudioEvent {
                device_id: device_id.to_string(),
                event_type: AudioEventType::DeviceDisconnected,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            true
        } else {
            false
        }
    }

    pub fn start_recording(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), AudioError> {
        if let Some(device) = self.devices.iter_mut().find(|d| d.id == device_id) {
            device.active = true;
            device.last_activity = Some(Utc::now());
            let event = AudioEvent {
                device_id: device_id.to_string(),
                event_type: AudioEventType::RecordingStarted,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(AudioError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn stop_recording(
        &mut self,
        device_id: &str,
    ) -> std::result::Result<(), AudioError> {
        if let Some(device) = self.devices.iter_mut().find(|d| d.id == device_id) {
            device.active = false;
            let event = AudioEvent {
                device_id: device_id.to_string(),
                event_type: AudioEventType::RecordingStopped,
                timestamp: Utc::now(),
            };
            self.events.push(event);
            Ok(())
        } else {
            Err(AudioError::DeviceNotFound(device_id.to_string()))
        }
    }

    pub fn check_unauthorized_capture(&self, process: &ProcessInfo) -> Option<AudioAlert> {
        if self.known_unauthorized.contains(&process.name) {
            let active_device = self.devices.iter().find(|d| d.active);
            let device_id = active_device
                .map(|d| d.id.clone())
                .unwrap_or_else(|| "unknown".to_string());

            Some(AudioAlert {
                device_id,
                process_name: process.name.clone(),
                pid: process.pid,
                severity: EventSeverity::Critical,
                timestamp: Utc::now(),
            })
        } else {
            None
        }
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn get_devices(&self) -> &[AudioDevice] {
        &self.devices
    }

    pub fn mark_unauthorized(&mut self, process_name: &str) {
        if !self.known_unauthorized.contains(&process_name.to_string()) {
            self.known_unauthorized.push(process_name.to_string());
        }
    }
}

#[async_trait]
impl SecurityModule for AudioCollector {
    fn name(&self) -> &str {
        "Audio Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors audio capture devices and detects unauthorized recording"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Audio Collector initialized");
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

    #[test]
    fn test_new_collector() {
        let collector = AudioCollector::new(test_bus());
        assert_eq!(collector.device_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_add_remove_device() {
        let mut collector = AudioCollector::new(test_bus());
        let device = AudioDevice {
            id: "mic1".into(),
            name: "USB Microphone".into(),
            driver: "usb audio".into(),
            active: false,
            last_activity: None,
        };
        collector.add_device(device);
        assert_eq!(collector.device_count(), 1);
        assert!(collector.remove_device("mic1"));
        assert_eq!(collector.device_count(), 0);
        assert!(!collector.remove_device("nonexistent"));
    }

    #[test]
    fn test_start_stop_recording() {
        let mut collector = AudioCollector::new(test_bus());
        let device = AudioDevice {
            id: "mic1".into(),
            name: "Built-in Mic".into(),
            driver: "realtek".into(),
            active: false,
            last_activity: None,
        };
        collector.add_device(device);
        assert!(collector.start_recording("mic1").is_ok());
        assert!(collector.get_devices()[0].active);
        assert!(collector.stop_recording("mic1").is_ok());
        assert!(!collector.get_devices()[0].active);
        assert!(collector.start_recording("nonexistent").is_err());
    }

    #[test]
    fn test_collect_events() {
        let mut collector = AudioCollector::new(test_bus());
        let device = AudioDevice {
            id: "mic1".into(),
            name: "Mic".into(),
            driver: "driver".into(),
            active: false,
            last_activity: None,
        };
        collector.add_device(device);
        let events = collector.collect_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AudioEventType::DeviceConnected);
        assert!(collector.collect_events().is_empty());
    }

    #[test]
    fn test_unauthorized_capture_detection() {
        let mut collector = AudioCollector::new(test_bus());
        let device = AudioDevice {
            id: "mic1".into(),
            name: "Mic".into(),
            driver: "driver".into(),
            active: true,
            last_activity: None,
        };
        collector.add_device(device);

        let normal_process = ProcessInfo {
            name: "notepad.exe".into(),
            ..Default::default()
        };
        assert!(collector.check_unauthorized_capture(&normal_process).is_none());

        let bad_process = ProcessInfo {
            name: "keylogger.exe".into(),
            pid: 999,
            ..Default::default()
        };
        let alert = collector.check_unauthorized_capture(&bad_process);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, EventSeverity::Critical);
        assert_eq!(alert.pid, 999);
    }

    #[test]
    fn test_mark_unauthorized() {
        let mut collector = AudioCollector::new(test_bus());
        collector.mark_unauthorized("evil.exe");
        let process = ProcessInfo {
            name: "evil.exe".into(),
            ..Default::default()
        };
        assert!(collector.check_unauthorized_capture(&process).is_some());
    }

    #[test]
    fn test_start_stop_collector() {
        let mut collector = AudioCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_recording_events() {
        let mut collector = AudioCollector::new(test_bus());
        let device = AudioDevice {
            id: "mic1".into(),
            name: "Mic".into(),
            driver: "driver".into(),
            active: false,
            last_activity: None,
        };
        collector.add_device(device);
        let _ = collector.start_recording("mic1");
        let _ = collector.stop_recording("mic1");
        let events = collector.collect_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].event_type, AudioEventType::RecordingStarted);
        assert_eq!(events[2].event_type, AudioEventType::RecordingStopped);
    }
}
