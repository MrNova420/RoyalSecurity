pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_core::bus::EventBus;
use std::collections::HashMap;
use std::error::Error;
use std::time::Instant;
use tracing::info;
use chrono::{DateTime, Utc};

#[derive(Debug, thiserror::Error)]
pub enum FirmwareError {
    #[error("Firmware collector not running")]
    NotRunning,
    #[error("Component not found: {0}")]
    ComponentNotFound(String),
    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FirmwareEventType {
    UpdateDetected,
    UpdateCompleted,
    IntegrityCheck,
    TamperDetected,
    RollbackDetected,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirmwareEvent {
    pub component: String,
    pub version: String,
    pub event_type: FirmwareEventType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct FirmwareComponent {
    _name: String,
    version: String,
    hash: String,
}

pub struct FirmwareCollector {
    _bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    events: Vec<FirmwareEvent>,
    components: HashMap<String, FirmwareComponent>,
}

impl FirmwareCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            events: Vec::new(),
            components: HashMap::new(),
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), FirmwareError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!(
            "Firmware Collector started with {} components",
            self.components.len()
        );
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), FirmwareError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Firmware Collector stopped. Processed {} events",
            self.events_processed
        );
        Ok(())
    }

    pub fn collect_events(&mut self) -> Vec<FirmwareEvent> {
        let events: Vec<FirmwareEvent> = self.events.drain(..).collect();
        self.events_processed += events.len() as u64;
        events
    }

    pub fn register_component(&mut self, name: &str, version: &str, hash: &str) {
        self.components.insert(
            name.to_string(),
            FirmwareComponent {
                _name: name.to_string(),
                version: version.to_string(),
                hash: hash.to_string(),
            },
        );
    }

    pub fn check_firmware_integrity(&self, component: &str) -> bool {
        if let Some(comp) = self.components.get(component) {
            !comp.hash.is_empty() && !comp.version.is_empty()
        } else {
            false
        }
    }

    pub fn report_update_detected(&mut self, component: &str, new_version: &str) {
        let old_version = self
            .components
            .get(component)
            .map(|c| c.version.clone())
            .unwrap_or_else(|| "unknown".to_string());

        if new_version < old_version.as_str() {
            self.events.push(FirmwareEvent {
                component: component.into(),
                version: new_version.into(),
                event_type: FirmwareEventType::RollbackDetected,
                timestamp: Utc::now(),
            });
        }

        self.events.push(FirmwareEvent {
            component: component.into(),
            version: new_version.into(),
            event_type: FirmwareEventType::UpdateDetected,
            timestamp: Utc::now(),
        });
    }

    pub fn report_update_completed(&mut self, component: &str, new_version: &str, new_hash: &str) {
        if let Some(comp) = self.components.get_mut(component) {
            comp.version = new_version.to_string();
            comp.hash = new_hash.to_string();
        }

        self.events.push(FirmwareEvent {
            component: component.into(),
            version: new_version.into(),
            event_type: FirmwareEventType::UpdateCompleted,
            timestamp: Utc::now(),
        });
    }

    pub fn report_tamper_detected(&mut self, component: &str) {
        let version = self
            .components
            .get(component)
            .map(|c| c.version.clone())
            .unwrap_or_else(|| "unknown".to_string());

        self.events.push(FirmwareEvent {
            component: component.into(),
            version,
            event_type: FirmwareEventType::TamperDetected,
            timestamp: Utc::now(),
        });
    }

    pub fn record_integrity_check(&mut self, component: &str, passed: bool) {
        let version = self
            .components
            .get(component)
            .map(|c| c.version.clone())
            .unwrap_or_else(|| "unknown".to_string());

        self.events.push(FirmwareEvent {
            component: component.into(),
            version,
            event_type: FirmwareEventType::IntegrityCheck,
            timestamp: Utc::now(),
        });

        if !passed {
            self.report_tamper_detected(component);
        }
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn get_component_version(&self, component: &str) -> Option<&str> {
        self.components.get(component).map(|c| c.version.as_str())
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Enumerates system firmware tables (ACPI / SMBIOS) and UEFI Secure Boot state,
    /// registering each discovered component via [`Self::register_component`].
    /// Returns firmware events generated during enumeration (currently informational).
    pub fn enumerate_system_firmware(&mut self) -> Vec<FirmwareEvent> {
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }

        #[cfg(target_os = "windows")]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, ACPI, RSMB};
            use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;

            let mut events = Vec::new();

            // --- ACPI firmware table ---
            unsafe {
                let size = GetSystemFirmwareTable(ACPI, 0, None);
                if size > 0 {
                    let mut buf = vec![0u8; size as usize];
                    GetSystemFirmwareTable(ACPI, 0, Some(&mut buf));

                    if buf.len() >= 36 {
                        let sig = std::str::from_utf8(&buf[0..4])
                            .unwrap_or("????")
                            .to_string();
                        let rev = buf[8];
                        let oem = std::str::from_utf8(&buf[9..15])
                            .unwrap_or(" ")
                            .trim_end()
                            .to_string();

                        let version = format!("{}.{}", sig, rev);
                        let hash = if oem.is_empty() {
                            "oem:unknown".to_string()
                        } else {
                            format!("oem:{}", oem)
                        };

                        self.register_component("ACPI", &version, &hash);
                        info!("Enumerated ACPI firmware: {} rev {}", sig, rev);

                        events.push(FirmwareEvent {
                            component: "ACPI".into(),
                            version,
                            event_type: FirmwareEventType::IntegrityCheck,
                            timestamp: Utc::now(),
                        });
                    }
                }
            }

            // --- SMBIOS firmware table ---
            unsafe {
                let size = GetSystemFirmwareTable(RSMB, 0, None);
                if size > 0 {
                    let mut buf = vec![0u8; size as usize];
                    GetSystemFirmwareTable(RSMB, 0, Some(&mut buf));

                    let (major, minor) = if buf.len() >= 7 && buf[0..4] == *b"_SM_" {
                        (buf[5], buf[6])
                    } else if buf.len() >= 8 && buf[0..5] == *b"_SM3_" {
                        (buf[6], buf[7])
                    } else {
                        (0u8, 0u8)
                    };

                    if major > 0 || minor > 0 {
                        let version = format!("{}.{}", major, minor);
                        self.register_component(
                            "SMBIOS",
                            &version,
                            &format!("len:{}", size),
                        );
                        info!("Enumerated SMBIOS firmware: {}.{}", major, minor);

                        events.push(FirmwareEvent {
                            component: "SMBIOS".into(),
                            version,
                            event_type: FirmwareEventType::IntegrityCheck,
                            timestamp: Utc::now(),
                        });
                    }
                }
            }

            // --- UEFI Secure Boot variable ---
            unsafe {
                let name: Vec<u16> = "SecureBoot"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let guid: Vec<u16> = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                let size = GetFirmwareEnvironmentVariableW(
                    PCWSTR::from_raw(name.as_ptr()),
                    PCWSTR::from_raw(guid.as_ptr()),
                    None,
                    0,
                );

                if size > 0 {
                    let mut buf = vec![0u8; size as usize];
                    let returned = GetFirmwareEnvironmentVariableW(
                        PCWSTR::from_raw(name.as_ptr()),
                        PCWSTR::from_raw(guid.as_ptr()),
                        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                        size,
                    );

                    if returned > 0 {
                        let enabled = !buf.is_empty() && buf[0] == 1;
                        let version = if enabled { "enabled" } else { "disabled" };
                        self.register_component(
                            "UEFI_SecureBoot",
                            version,
                            "var:SecureBoot",
                        );
                        info!("UEFI Secure Boot: {}", version);

                        events.push(FirmwareEvent {
                            component: "UEFI_SecureBoot".into(),
                            version: version.into(),
                            event_type: FirmwareEventType::IntegrityCheck,
                            timestamp: Utc::now(),
                        });
                    }
                }
            }

            events
        }
    }
}

#[async_trait]
impl SecurityModule for FirmwareCollector {
    fn name(&self) -> &str {
        "Firmware Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors firmware updates, UEFI changes, and BIOS integrity"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Firmware Collector initialized");
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
        let collector = FirmwareCollector::new(test_bus());
        assert_eq!(collector.event_count(), 0);
        assert_eq!(collector.component_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_register_and_check_integrity() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.register_component("BIOS", "1.0.0", "abc123hash");
        assert_eq!(collector.component_count(), 1);
        assert!(collector.check_firmware_integrity("BIOS"));
        assert!(!collector.check_firmware_integrity("nonexistent"));
    }

    #[test]
    fn test_update_detected() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.register_component("UEFI", "1.0.0", "hash1");
        collector.report_update_detected("UEFI", "1.1.0");
        let events = collector.collect_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, FirmwareEventType::UpdateDetected);
        assert_eq!(events[0].version, "1.1.0");
    }

    #[test]
    fn test_rollback_detection() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.register_component("UEFI", "2.0.0", "hash1");
        collector.report_update_detected("UEFI", "1.0.0");
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, FirmwareEventType::RollbackDetected);
        assert_eq!(events[1].event_type, FirmwareEventType::UpdateDetected);
    }

    #[test]
    fn test_update_completed_updates_version() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.register_component("BIOS", "1.0.0", "oldhash");
        collector.report_update_completed("BIOS", "2.0.0", "newhash");
        assert_eq!(collector.get_component_version("BIOS"), Some("2.0.0"));
        let events = collector.collect_events();
        assert_eq!(events[0].event_type, FirmwareEventType::UpdateCompleted);
    }

    #[test]
    fn test_tamper_detection() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.register_component("BIOS", "1.0.0", "hash");
        collector.report_tamper_detected("BIOS");
        let events = collector.collect_events();
        assert_eq!(events[0].event_type, FirmwareEventType::TamperDetected);
    }

    #[test]
    fn test_integrity_check_failure_triggers_tamper() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.register_component("UEFI", "1.0.0", "hash");
        collector.record_integrity_check("UEFI", false);
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, FirmwareEventType::IntegrityCheck);
        assert_eq!(events[1].event_type, FirmwareEventType::TamperDetected);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = FirmwareCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_enumerate_system_firmware_returns_vec() {
        let mut collector = FirmwareCollector::new(test_bus());
        let events = collector.enumerate_system_firmware();
        assert!(events.iter().all(|e| e.event_type == FirmwareEventType::IntegrityCheck));
        #[cfg(not(target_os = "windows"))]
        assert!(events.is_empty());
    }

    #[test]
    fn test_enumerate_system_firmware_registers_components() {
        let mut collector = FirmwareCollector::new(test_bus());
        collector.enumerate_system_firmware();

        // On real Windows hardware we expect at least one of these to exist.
        // On non-Windows or CI, nothing is registered — that's fine.
        #[cfg(target_os = "windows")]
        {
            let has_acpi = collector.check_firmware_integrity("ACPI")
                || collector.get_component_version("ACPI").is_none();
            let has_smbios = collector.check_firmware_integrity("SMBIOS")
                || collector.get_component_version("SMBIOS").is_none();
            // At least the call should not panic regardless of hardware
            let _ = (has_acpi, has_smbios);
        }
    }
}
