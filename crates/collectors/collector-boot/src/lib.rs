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
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error("Boot collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum BootEventType {
    SystemBoot,
    SystemShutdown,
    BootConfigChanged,
    DriverLoaded,
    StartupItemAdded,
    SuspiciousStartup,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootEvent {
    pub event_type: BootEventType,
    pub details: String,
    pub key_path: Option<String>,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub struct BootCollector {
    bus: Arc<EventBus>,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    events: Vec<BootEvent>,
    boot_times: Vec<DateTime<Utc>>,
    boot_count: u64,
    startup_keys: Vec<String>,
}

unsafe impl Send for BootCollector {}
unsafe impl Sync for BootCollector {}

impl BootCollector {
    pub fn new(bus: EventBus) -> Self {
        let mut startup_keys = Vec::new();
        startup_keys.push(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into());
        startup_keys.push(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce".into());
        startup_keys.push(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices".into());
        startup_keys.push(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce".into());
        startup_keys.push(r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run".into());
        startup_keys.push(r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce".into());
        startup_keys.push(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run".into());
        startup_keys.push(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon".into());
        startup_keys.push(r"SYSTEM\CurrentControlSet\Services".into());

        Self {
            bus: Arc::new(bus),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            events: Vec::new(),
            boot_times: Vec::new(),
            boot_count: 0,
            startup_keys,
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), BootError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("Boot Collector started");
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), BootError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Boot Collector stopped. Processed {} events",
            self.events_processed
        );
        Ok(())
    }

    pub fn collect_events(&mut self) -> Vec<BootEvent> {
        let events: Vec<BootEvent> = self.events.drain(..).collect();
        self.events_processed += events.len() as u64;
        events
    }

    #[cfg(target_os = "windows")]
    pub fn read_startup_items(&mut self) -> Vec<BootEvent> {
        use windows::Win32::System::Registry::{
            RegOpenKeyExW, RegEnumValueW, RegCloseKey, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER,
            KEY_READ,
        };

        let mut items = Vec::new();

        for key_path in &self.startup_keys {
            let is_hkcu = key_path.starts_with("SOFTWARE") && !key_path.starts_with("SYSTEM");
            let root = if is_hkcu { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };

            unsafe {
                let key_path_wide: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
                let mut hkey = Default::default();

                if RegOpenKeyExW(root, windows::core::PCWSTR(key_path_wide.as_ptr()), 0, KEY_READ, &mut hkey).is_ok() {
                    let mut index = 0;
                    loop {
                        let mut value_name = [0u16; 256];
                        let mut name_len = 256u32;
                        let mut value_data = [0u8; 4096];
                        let mut data_len = 4096u32;
                        let mut reg_type: u32 = 0;

                        let result = RegEnumValueW(
                            hkey,
                            index,
                            windows::core::PWSTR(value_name.as_mut_ptr()),
                            &mut name_len,
                            None,
                            Some(&mut reg_type),
                            Some(value_data.as_mut_ptr() as *mut u8),
                            Some(&mut data_len),
                        );

                        if result.is_err() {
                            break;
                        }

                        let name = String::from_utf16_lossy(&value_name[..name_len as usize]).to_string();
                        let data_str = match reg_type {
                            1 | 2 => {
                                let slice = &value_data[..data_len as usize];
                                String::from_utf16_lossy(
                                    slice.chunks(2)
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect::<Vec<_>>()
                                        .as_slice()
                                ).trim_end_matches('\0').to_string()
                            }
                            _ => format!("(type {})", reg_type),
                        };

                        let suspicious = data_str.to_lowercase().contains("powershell")
                            || data_str.to_lowercase().contains("cmd.exe /c")
                            || data_str.to_lowercase().contains("mshta")
                            || data_str.to_lowercase().contains("wscript")
                            || data_str.to_lowercase().contains("cscript")
                            || data_str.to_lowercase().contains("regsvr32")
                            || data_str.to_lowercase().contains("rundll32")
                            || data_str.to_lowercase().contains("certutil")
                            || data_str.to_lowercase().contains("bitsadmin");

                        let event_type = if suspicious {
                            BootEventType::SuspiciousStartup
                        } else {
                            BootEventType::StartupItemAdded
                        };

                        items.push(BootEvent {
                            event_type,
                            details: format!("Startup: {} = {}", name, data_str),
                            key_path: Some(key_path.clone()),
                            value_name: Some(name),
                            value_data: Some(data_str),
                            timestamp: Utc::now(),
                        });

                        index += 1;
                    }

                    let _ = RegCloseKey(hkey);
                }
            }
        }

        self.events.extend(items.clone());
        self.events_processed += items.len() as u64;
        items
    }

    #[cfg(not(target_os = "windows"))]
    pub fn read_startup_items(&mut self) -> Vec<BootEvent> {
        Vec::new()
    }

    #[cfg(target_os = "windows")]
    pub fn get_system_uptime(&self) -> Option<u64> {
        use windows::Win32::System::SystemInformation::GetTickCount64;
        unsafe {
            Some(GetTickCount64() / 1000)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_system_uptime(&self) -> Option<u64> {
        None
    }

    pub fn record_boot_time(&mut self) {
        let now = Utc::now();
        self.boot_times.push(now);
        self.boot_count += 1;
        self.events.push(BootEvent {
            event_type: BootEventType::SystemBoot,
            details: format!("System boot #{} recorded", self.boot_count),
            key_path: None,
            value_name: None,
            value_data: None,
            timestamp: now,
        });
    }

    pub fn record_shutdown(&mut self, reason: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::SystemShutdown,
            details: reason.to_string(),
            key_path: None,
            value_name: None,
            value_data: None,
            timestamp: Utc::now(),
        });
    }

    pub fn record_config_change(&mut self, details: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::BootConfigChanged,
            details: details.to_string(),
            key_path: None,
            value_name: None,
            value_data: None,
            timestamp: Utc::now(),
        });
    }

    pub fn record_driver_loaded(&mut self, driver_name: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::DriverLoaded,
            details: format!("Driver loaded: {}", driver_name),
            key_path: None,
            value_name: None,
            value_data: None,
            timestamp: Utc::now(),
        });
    }

    pub fn get_boot_history(&self) -> &[DateTime<Utc>] {
        &self.boot_times
    }

    pub fn boot_count(&self) -> u64 {
        self.boot_count
    }

    pub fn get_events(&self) -> &[BootEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn last_boot_time(&self) -> Option<DateTime<Utc>> {
        self.boot_times.last().copied()
    }

    pub fn time_since_last_boot(&self) -> Option<std::time::Duration> {
        self.boot_times.last().map(|t| Utc::now() - *t).map(|d| {
            std::time::Duration::from_millis(d.num_milliseconds() as u64)
        })
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }
}

#[async_trait]
impl SecurityModule for BootCollector {
    fn name(&self) -> &str {
        "Boot Collector"
    }
    fn version(&self) -> &str {
        "0.2.0"
    }
    fn description(&self) -> &str {
        "Real startup item detection via registry queries and boot event monitoring"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Boot Collector initialized");
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
        let collector = BootCollector::new(test_bus());
        assert_eq!(collector.boot_count(), 0);
        assert!(!collector.is_collecting());
        assert!(collector.get_boot_history().is_empty());
    }

    #[test]
    fn test_record_boot_time() {
        let mut collector = BootCollector::new(test_bus());
        collector.record_boot_time();
        assert_eq!(collector.boot_count(), 1);
        assert_eq!(collector.get_boot_history().len(), 1);
        collector.record_boot_time();
        assert_eq!(collector.boot_count(), 2);
    }

    #[test]
    fn test_collect_events() {
        let mut collector = BootCollector::new(test_bus());
        collector.record_boot_time();
        collector.record_shutdown("user logout");
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, BootEventType::SystemBoot);
        assert_eq!(events[1].event_type, BootEventType::SystemShutdown);
        assert!(collector.collect_events().is_empty());
    }

    #[test]
    fn test_record_various_events() {
        let mut collector = BootCollector::new(test_bus());
        collector.record_config_change("BCD modified");
        collector.record_driver_loaded("nvlddmkm.sys");
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, BootEventType::BootConfigChanged);
        assert_eq!(events[1].event_type, BootEventType::DriverLoaded);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = BootCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_boot_history_and_last_boot() {
        let mut collector = BootCollector::new(test_bus());
        assert!(collector.last_boot_time().is_none());
        assert!(collector.time_since_last_boot().is_none());
        collector.record_boot_time();
        assert!(collector.last_boot_time().is_some());
        assert!(collector.time_since_last_boot().is_some());
    }

    #[test]
    fn test_event_count() {
        let mut collector = BootCollector::new(test_bus());
        assert_eq!(collector.event_count(), 0);
        collector.record_boot_time();
        collector.record_shutdown("update");
        assert_eq!(collector.event_count(), 2);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_read_startup_items() {
        let mut collector = BootCollector::new(test_bus());
        let items = collector.read_startup_items();
        assert!(items.len() > 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_system_uptime() {
        let collector = BootCollector::new(test_bus());
        let uptime = collector.get_system_uptime();
        assert!(uptime.is_some());
        assert!(uptime.unwrap() > 0);
    }
}
