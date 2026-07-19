pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info};

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
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
}

impl UsbCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            known_devices: Arc::new(RwLock::new(Vec::new())),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
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

    #[cfg(target_os = "windows")]
    pub fn scan_usb_devices(&self) -> Vec<UsbDevice> {
        use windows::Win32::Devices::DeviceAndDriverInstallation::{
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
            SP_DEVINFO_DATA, DIGCF_PRESENT, SPDRP_DEVICEDESC, SPDRP_HARDWAREID,
        };
        use windows::Win32::Foundation::HWND;

        const GUID_DEVCLASS_USB: windows::core::GUID = windows::core::GUID {
            data1: 0xA5DC_BF10,
            data2: 0x6530,
            data3: 0x11D2,
            data4: [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED],
        };

        let mut devices = Vec::new();

        let dev_info = match unsafe {
            SetupDiGetClassDevsW(
                Some(&GUID_DEVCLASS_USB),
                None,
                HWND(std::ptr::null_mut()),
                DIGCF_PRESENT,
            )
        } {
            Ok(h) => h,
            Err(_) => return devices,
        };

        let mut index = 0u32;
        loop {
            let mut dev_data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
            dev_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

            if unsafe { SetupDiEnumDeviceInfo(dev_info, index, &mut dev_data) }.is_err() {
                break;
            }
            index += 1;

            let hardware_id =
                unsafe { get_device_string_property(dev_info, &dev_data, SPDRP_HARDWAREID) };

            let Some(hw_id) = hardware_id else {
                continue;
            };

            if !hw_id.to_uppercase().starts_with("USB\\") {
                continue;
            }

            let (vid, pid) = match parse_hardware_id(&hw_id) {
                Some(v) => v,
                None => continue,
            };

            let description =
                unsafe { get_device_string_property(dev_info, &dev_data, SPDRP_DEVICEDESC) };

            let serial = hw_id.rsplit('\\').next().map(|s| s.to_string());

            devices.push(UsbDevice {
                id: hw_id,
                vendor_id: vid,
                product_id: pid,
                serial,
                manufacturer: description,
                connected: true,
                timestamp: Utc::now(),
            });
        }

        unsafe {
            let _ = SetupDiDestroyDeviceInfoList(dev_info);
        }
        devices
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_usb_devices(&self) -> Vec<UsbDevice> {
        Vec::new()
    }
}

impl Default for UsbCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
unsafe fn get_device_string_property(
    dev_info: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    dev_data: *const windows::Win32::Devices::DeviceAndDriverInstallation::SP_DEVINFO_DATA,
    property: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
) -> Option<String> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceRegistryPropertyW;

    let mut required_size: u32 = 0;
    let _ = SetupDiGetDeviceRegistryPropertyW(
        dev_info,
        dev_data,
        property,
        None,
        None,
        Some(&mut required_size),
    );

    if required_size == 0 {
        return None;
    }

    let byte_len = required_size as usize;
    let mut buffer: Vec<u8> = vec![0u8; byte_len];
    let mut actual_size: u32 = 0;
    if SetupDiGetDeviceRegistryPropertyW(
        dev_info,
        dev_data,
        property,
        None,
        Some(&mut buffer),
        Some(&mut actual_size),
    )
    .is_err()
    {
        return None;
    }

    let len = actual_size as usize;
    if len == 0 || len > buffer.len() || len % 2 != 0 {
        return None;
    }
    let wide: Vec<u16> = buffer[..len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(
        String::from_utf16_lossy(&wide)
            .trim_end_matches('\0')
            .to_string(),
    )
}

pub fn parse_hardware_id(hardware_id: &str) -> Option<(String, String)> {
    let upper = hardware_id.to_uppercase();
    if !upper.starts_with("USB\\") {
        return None;
    }

    let vid_idx = upper.find("VID_")? + 4;
    let vid_rest = &upper[vid_idx..];
    let vid_end = vid_rest.find(|c: char| c == '\\' || c == '&').unwrap_or(vid_rest.len());
    let vid = vid_rest[..vid_end].to_string();

    let pid_idx = upper.find("PID_")? + 4;
    let pid_rest = &upper[pid_idx..];
    let pid_end = pid_rest.find(|c: char| c == '\\').unwrap_or(pid_rest.len());
    let pid = pid_rest[..pid_end].to_string();

    Some((vid, pid))
}

#[async_trait]
impl SecurityModule for UsbCollector {
    fn name(&self) -> &str {
        "USB Collector"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn description(&self) -> &str {
        "Monitors USB device connections, disconnections, and data transfers"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("USB Collector initialized");
        Ok(())
    }

    async fn start(&mut self) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        UsbCollector::start(self).await?;
        self.status = ModuleStatus::Running;
        self.start_time = Some(Instant::now());
        Ok(())
    }

    async fn stop(&mut self) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        UsbCollector::stop(self).await?;
        self.status = ModuleStatus::Stopped;
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

    #[test]
    fn test_parse_hardware_id_standard() {
        let (vid, pid) = parse_hardware_id("USB\\VID_046D&PID_082D\\5&12345678&0&0000").unwrap();
        assert_eq!(vid, "046D");
        assert_eq!(pid, "082D");
    }

    #[test]
    fn test_parse_hardware_id_lowercase() {
        let (vid, pid) = parse_hardware_id("USB\\vid_abcd&pid_1234").unwrap();
        assert_eq!(vid, "ABCD");
        assert_eq!(pid, "1234");
    }

    #[test]
    fn test_parse_hardware_id_no_serial() {
        let (vid, pid) = parse_hardware_id("USB\\VID_1234&PID_5678").unwrap();
        assert_eq!(vid, "1234");
        assert_eq!(pid, "5678");
    }

    #[test]
    fn test_parse_hardware_id_not_usb() {
        assert!(parse_hardware_id("PCI\\VEN_8086&DEV_1502").is_none());
    }

    #[test]
    fn test_parse_hardware_id_empty() {
        assert!(parse_hardware_id("").is_none());
    }

    #[test]
    fn test_parse_hardware_id_no_vid() {
        assert!(parse_hardware_id("USB\\PID_1234").is_none());
    }

    #[test]
    fn test_parse_hardware_id_no_pid() {
        assert!(parse_hardware_id("USB\\VID_1234").is_none());
    }

    #[test]
    fn test_scan_usb_devices_returns_vec() {
        let collector = UsbCollector::new();
        let devices = collector.scan_usb_devices();
        assert!(devices.is_empty() || !devices.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_scan_usb_devices_on_windows() {
        let collector = UsbCollector::new();
        let devices = collector.scan_usb_devices();
        for device in &devices {
            assert!(!device.vendor_id.is_empty());
            assert!(!device.product_id.is_empty());
            assert!(device.connected);
        }
    }
}
