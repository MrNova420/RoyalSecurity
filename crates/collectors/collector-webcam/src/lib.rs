pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WebcamEventType {
    AccessGranted,
    AccessDenied,
    SnapshotCaptured,
    RecordingStarted,
    RecordingStopped,
}

impl std::fmt::Display for WebcamEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebcamEventType::AccessGranted => write!(f, "AccessGranted"),
            WebcamEventType::AccessDenied => write!(f, "AccessDenied"),
            WebcamEventType::SnapshotCaptured => write!(f, "SnapshotCaptured"),
            WebcamEventType::RecordingStarted => write!(f, "RecordingStarted"),
            WebcamEventType::RecordingStopped => write!(f, "RecordingStopped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebcamEvent {
    pub device_name: String,
    pub process_name: String,
    pub pid: u32,
    pub event_type: WebcamEventType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebcamAlert {
    pub device_name: String,
    pub process_name: String,
    pub pid: u32,
    pub event_type: WebcamEventType,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum WebcamCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid webcam event: {0}")]
    InvalidEvent(String),
}

pub struct WebcamCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<WebcamEvent>>>,
    allowed_processes: Arc<RwLock<Vec<String>>>,
}

impl WebcamCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            allowed_processes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self)  -> std::result::Result<(), WebcamCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("Webcam collector started");
        Ok(())
    }

    pub async fn stop(&self)  -> std::result::Result<(), WebcamCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("Webcam collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn allow_process(&self, process_name: &str) {
        let mut allowed = self.allowed_processes.write().await;
        if !allowed.contains(&process_name.to_string()) {
            allowed.push(process_name.to_string());
        }
    }

    pub async fn remove_allowed_process(&self, process_name: &str) {
        let mut allowed = self.allowed_processes.write().await;
        allowed.retain(|p| p != process_name);
    }

    pub async fn is_process_allowed(&self, process_name: &str) -> bool {
        self.allowed_processes
            .read()
            .await
            .iter()
            .any(|p| p == process_name)
    }

    pub async fn capture_event(&self, event: WebcamEvent)  -> std::result::Result<(), WebcamCollectorError> {
        if !*self.running.read().await {
            return Err(WebcamCollectorError::NotStarted.into());
        }
        if event.device_name.is_empty() {
            return Err(WebcamCollectorError::InvalidEvent(
                "Empty device name".into(),
            )
            .into());
        }
        debug!(
            device = %event.device_name,
            process = %event.process_name,
            event_type = %event.event_type,
            pid = event.pid,
            "Captured webcam event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    pub async fn check_unauthorized_access(
        &self,
        process: &ProcessInfo,
    ) -> Option<WebcamAlert> {
        let allowed = self.allowed_processes.read().await;
        if allowed.iter().any(|p| p == &process.name) {
            return None;
        }
        Some(WebcamAlert {
            device_name: "Default Webcam".to_string(),
            process_name: process.name.clone(),
            pid: process.pid,
            event_type: WebcamEventType::AccessDenied,
            severity: EventSeverity::High,
            timestamp: Utc::now(),
        })
    }

    pub async fn get_events(&self) -> Vec<WebcamEvent> {
        self.events.read().await.clone()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        debug!("Webcam collector cleared all events");
    }

    #[cfg(target_os = "windows")]
    pub fn enumerate_camera_devices(&self) -> Vec<WebcamEvent> {
        use windows::Win32::Devices::DeviceAndDriverInstallation::{
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
            SetupDiGetDeviceRegistryPropertyW, SP_DEVINFO_DATA, DIGCF_PRESENT, SPDRP_DEVICEDESC,
        };
        const KSCATEGORY_VIDEO_CAMERA: windows::core::GUID = windows::core::GUID {
            data1: 0xE5323777,
            data2: 0xF976,
            data3: 0x4f5b,
            data4: [0x9B, 0x55, 0xB9, 0x46, 0x99, 0xC4, 0x6E, 0x44],
        };

        let mut devices = Vec::new();

        unsafe {
            let dev_info_set = match SetupDiGetClassDevsW(
                Some(&KSCATEGORY_VIDEO_CAMERA),
                windows::core::PCWSTR::null(),
                None,
                DIGCF_PRESENT,
            ) {
                Ok(set) => set,
                Err(e) => {
                    debug!("SetupDiGetClassDevsW for camera failed: {}", e);
                    return devices;
                }
            };

            let mut index = 0u32;
            loop {
                let mut dev_info_data: SP_DEVINFO_DATA = std::mem::zeroed();
                dev_info_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

                if SetupDiEnumDeviceInfo(dev_info_set, index, &mut dev_info_data).is_err() {
                    break;
                }
                index += 1;

                let mut desc_buf = [0u8; 512];
                let device_name = if SetupDiGetDeviceRegistryPropertyW(
                    dev_info_set,
                    &dev_info_data,
                    SPDRP_DEVICEDESC,
                    None,
                    Some(&mut desc_buf),
                    None,
                )
                .is_ok()
                {
                    let wide = std::slice::from_raw_parts(
                        desc_buf.as_ptr() as *const u16,
                        desc_buf.len() / 2,
                    );
                    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                    String::from_utf16_lossy(&wide[..len])
                } else {
                    "Unknown Camera".to_string()
                };

                info!("Enumerated camera device: {}", device_name);
                devices.push(WebcamEvent {
                    device_name,
                    process_name: "system".to_string(),
                    pid: 0,
                    event_type: WebcamEventType::AccessGranted,
                    timestamp: Utc::now(),
                });
            }

            let _ = SetupDiDestroyDeviceInfoList(dev_info_set);
        }

        devices
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enumerate_camera_devices(&self) -> Vec<WebcamEvent> {
        debug!("Camera enumeration not supported on this platform");
        Vec::new()
    }
}

impl Default for WebcamCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(process: &str, event_type: WebcamEventType) -> WebcamEvent {
        WebcamEvent {
            device_name: "HD Webcam".to_string(),
            process_name: process.to_string(),
            pid: 5678,
            event_type,
            timestamp: Utc::now(),
        }
    }

    fn make_process_info(name: &str, pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 0,
            name: name.to_string(),
            path: format!("C:\\{}.exe", name),
            command_line: String::new(),
            user: "USER".to_string(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = WebcamCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = WebcamCollector::new();
        let event = make_event("browser", WebcamEventType::AccessGranted);
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = WebcamCollector::new();
        collector.start().await.unwrap();
        let event = make_event("browser", WebcamEventType::AccessGranted);
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_device() {
        let collector = WebcamCollector::new();
        collector.start().await.unwrap();
        let event = WebcamEvent {
            device_name: String::new(),
            process_name: "test".into(),
            pid: 1,
            event_type: WebcamEventType::AccessGranted,
            timestamp: Utc::now(),
        };
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_unauthorized_access_detected() {
        let collector = WebcamCollector::new();
        let proc = make_process_info("malware", 9999);
        let alert = collector.check_unauthorized_access(&proc).await;
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, EventSeverity::High);
    }

    #[tokio::test]
    async fn test_allowed_process_no_alert() {
        let collector = WebcamCollector::new();
        collector.allow_process("teams.exe").await;
        let proc = make_process_info("teams.exe", 1234);
        assert!(collector.check_unauthorized_access(&proc).await.is_none());
    }

    #[tokio::test]
    async fn test_remove_allowed_process() {
        let collector = WebcamCollector::new();
        collector.allow_process("teams.exe").await;
        assert!(collector.is_process_allowed("teams.exe").await);
        collector.remove_allowed_process("teams.exe").await;
        assert!(!collector.is_process_allowed("teams.exe").await);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = WebcamCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event("browser", WebcamEventType::RecordingStarted))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }

    #[test]
    fn test_enumerate_camera_devices_returns_vec() {
        let collector = WebcamCollector::new();
        let devices = collector.enumerate_camera_devices();
        let _ = devices;
    }

    #[test]
    fn test_enumerate_camera_devices_event_fields() {
        let collector = WebcamCollector::new();
        let devices = collector.enumerate_camera_devices();
        for device in &devices {
            assert!(!device.device_name.is_empty());
            assert_eq!(device.process_name, "system");
            assert_eq!(device.pid, 0);
        }
    }

    #[test]
    fn test_enumerate_camera_devices_type() {
        let collector = WebcamCollector::new();
        let devices = collector.enumerate_camera_devices();
        for device in &devices {
            assert_eq!(device.event_type, WebcamEventType::AccessGranted);
        }
    }
}

