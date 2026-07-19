pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_core::bus::EventBus;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use chrono::{DateTime, Utc};

#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::*;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, strum_macros::Display)]
pub enum LogSource {
    Security,
    System,
    Application,
    PowerShell,
    Sysmon,
    WmiActivity,
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("Log collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub source: LogSource,
    pub level: String,
    pub message: String,
    pub event_id: u32,
    pub provider: String,
    pub timestamp: DateTime<Utc>,
}

pub struct LogCollector {
    bus: Arc<EventBus>,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    entries: Vec<LogEntry>,
    max_entries: usize,
}

impl LogCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus: Arc::new(bus),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            entries: Vec::new(),
            max_entries: 500_000,
        }
    }

    pub fn with_max_entries(bus: EventBus, max: usize) -> Self {
        Self {
            max_entries: max,
            ..Self::new(bus)
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), LogError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!(
            "Log Collector started with {} entries",
            self.entries.len()
        );
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), LogError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Log Collector stopped. Collected {} entries",
            self.entries.len()
        );
        Ok(())
    }

    pub fn collect_entry(&mut self, entry: LogEntry) {
        self.publish_to_bus(&entry);
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    fn publish_to_bus(&self, entry: &LogEntry) {
        let _severity = match entry.level.to_lowercase().as_str() {
            "error" | "critical" | "audit failure" => EventSeverity::High,
            "warning" | "audit success" => EventSeverity::Medium,
            _ => EventSeverity::Informational,
        };

        let _event_type = match entry.event_id {
            4624 => EventType::AuthSuccess,
            4625 => EventType::AuthFailure,
            4672 => EventType::PrivilegeEscalation,
            4688 => EventType::ProcessCreated,
            4689 => EventType::ProcessTerminated,
            4697 => EventType::ServiceCreated,
            4698 => EventType::ScheduledTaskCreated,
            4720 => EventType::ServiceCreated,
            4732 => EventType::LateralMovement,
            7034 => EventType::ServiceStopped,
            7036 => EventType::ServiceStarted,
            1102 => EventType::ServiceStopped,
            _ => EventType::ProcessCreated,
        };

        let security_event = SecurityEvent::Process(ProcessInfo {
            pid: 0,
            name: format!("{}:{}", entry.source, entry.event_id),
            command_line: entry.message.clone(),
            user: entry.provider.clone(),
            timestamp: entry.timestamp,
            ..ProcessInfo::default()
        });

        if let Err(e) = self.bus.publish(security_event) {
            warn!("Failed to publish log event to bus: {}", e);
        }
    }

    pub fn get_entries(&self) -> Vec<&LogEntry> {
        self.entries.iter().collect()
    }

    pub fn get_entries_by_source(&self, source: LogSource) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| e.source == source).collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn purge_old(&mut self, max_age_secs: u64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        self.entries.retain(|e| e.timestamp > cutoff);
    }

    pub fn get_entries_by_level(&self, level: &str) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.level.eq_ignore_ascii_case(level))
            .collect()
    }

    pub fn get_entries_by_event_id(&self, event_id: u32) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.event_id == event_id)
            .collect()
    }

    pub fn get_entries_by_provider(&self, provider: &str) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.provider == provider)
            .collect()
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
    }

    pub fn source_counts(&self) -> HashMap<LogSource, usize> {
        let mut counts = HashMap::new();
        for entry in &self.entries {
            *counts.entry(entry.source.clone()).or_insert(0) += 1;
        }
        counts
    }

    #[cfg(target_os = "windows")]
    fn source_to_channel(source: &LogSource) -> &'static str {
        match source {
            LogSource::Security => "Security",
            LogSource::System => "System",
            LogSource::Application => "Application",
            LogSource::PowerShell => "Windows PowerShell",
            LogSource::Sysmon => "Microsoft-Windows-Sysmon/Operational",
            LogSource::WmiActivity => "Microsoft-Windows-WMI-Activity/Operational",
        }
    }

    #[cfg(target_os = "windows")]
    fn event_type_to_string(event_type: u32) -> String {
        match event_type {
            1 => "Error".into(),
            2 => "Warning".into(),
            3 => "Information".into(),
            4 => "Audit Success".into(),
            5 => "Audit Failure".into(),
            _ => format!("Unknown({})", event_type),
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_eventlogrecord(record: &EVENTLOGRECORD, source: LogSource) -> Option<LogEntry> {
        if record.NumStrings == 0 {
            return None;
        }

        let data = unsafe {
            let data_ptr = (record as *const EVENTLOGRECORD as *const u8)
                .add(record.StringOffset as usize);
            let data_len = record.Length as usize - record.StringOffset as usize;
            std::slice::from_raw_parts(data_ptr, data_len)
        };

        let message = if let Some(first_null) = data.iter().position(|&b| b == 0) {
            String::from_utf16_lossy(
                data[..first_null]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<u16>>()
                    .as_slice(),
            )
        } else {
            String::from_utf16_lossy(
                data.chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<u16>>()
                    .as_slice(),
            )
        };

        let timestamp = chrono::DateTime::from_timestamp(record.TimeGenerated as i64, 0)
            .unwrap_or_else(Utc::now);

        Some(LogEntry {
            source,
            level: Self::event_type_to_string(record.EventType.0.into()),
            message,
            event_id: record.EventID & 0xFFFF,
            provider: format!("EventRecord#{}", record.RecordNumber),
            timestamp,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn poll_real_events(&mut self) -> u32 {
        let mut count = 0u32;
        let channels = [
            LogSource::Security,
            LogSource::System,
            LogSource::Application,
        ];

        for source in &channels {
            let channel_name = Self::source_to_channel(source);
            let channel_wide: Vec<u16> = channel_name.encode_utf16().chain(std::iter::once(0)).collect();

            let hlog = unsafe {
                match OpenEventLogW(PCWSTR::null(), PCWSTR(channel_wide.as_ptr())) {
                    Ok(h) if !h.0.is_null() => h,
                    _ => continue,
                }
            };

            let mut buffer_size = 65536u32;
            let mut buffer = vec![0u8; buffer_size as usize];
            let mut bytes_read = 0u32;
            let mut min_needed = 0u32;

            loop {
                match unsafe {
                    ReadEventLogW(
                        hlog,
                        READ_EVENT_LOG_READ_FLAGS(0x0001),
                        0,
                        buffer.as_mut_ptr() as *mut _,
                        buffer_size,
                        &mut bytes_read,
                        &mut min_needed,
                    )
                } {
                    Ok(()) => {
                        if bytes_read == 0 {
                            break;
                        }
                        let mut offset = 0usize;
                        while offset + std::mem::size_of::<EVENTLOGRECORD>() <= bytes_read as usize {
                            let record = unsafe {
                                &*((buffer.as_ptr().add(offset)) as *const EVENTLOGRECORD)
                            };
                            if record.Length == 0 {
                                break;
                            }
                            if let Some(entry) = Self::parse_eventlogrecord(record, source.clone()) {
                                self.collect_entry(entry);
                                count += 1;
                            }
                            offset += record.Length as usize;
                            if offset >= bytes_read as usize {
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        if min_needed > buffer_size {
                            buffer_size = min_needed;
                            buffer.resize(buffer_size as usize, 0);
                            continue;
                        }
                        break;
                    }
                }
            }

            unsafe {
                let _ = CloseEventLog(hlog);
            }
        }
        count
    }
}

#[async_trait]
impl SecurityModule for LogCollector {
    fn name(&self) -> &str {
        "Log Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Collects Windows Event Logs from Security, System, Application, PowerShell, and more"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Log Collector initialized");
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

    fn test_entry(source: LogSource, level: &str, event_id: u32) -> LogEntry {
        LogEntry {
            source,
            level: level.into(),
            message: format!("Test message {}", event_id),
            event_id,
            provider: "TestProvider".into(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_new_collector() {
        let collector = LogCollector::new(test_bus());
        assert_eq!(collector.entry_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_collect_entry() {
        let mut collector = LogCollector::new(test_bus());
        collector.collect_entry(test_entry(LogSource::Security, "Error", 4625));
        collector.collect_entry(test_entry(LogSource::System, "Info", 7036));
        assert_eq!(collector.entry_count(), 2);
    }

    #[test]
    fn test_get_entries_by_source() {
        let mut collector = LogCollector::new(test_bus());
        collector.collect_entry(test_entry(LogSource::Security, "Error", 4625));
        collector.collect_entry(test_entry(LogSource::System, "Info", 7036));
        collector.collect_entry(test_entry(LogSource::Security, "Warning", 4688));
        let security = collector.get_entries_by_source(LogSource::Security);
        assert_eq!(security.len(), 2);
        let system = collector.get_entries_by_source(LogSource::System);
        assert_eq!(system.len(), 1);
    }

    #[test]
    fn test_purge_old() {
        let mut collector = LogCollector::new(test_bus());
        let mut old_entry = test_entry(LogSource::Security, "Error", 1);
        old_entry.timestamp = Utc::now() - chrono::Duration::seconds(3600);
        collector.collect_entry(old_entry);
        collector.collect_entry(test_entry(LogSource::Security, "Info", 2));
        assert_eq!(collector.entry_count(), 2);
        collector.purge_old(1800);
        assert_eq!(collector.entry_count(), 1);
    }

    #[test]
    fn test_max_entries_overflow() {
        let mut collector = LogCollector::with_max_entries(test_bus(), 3);
        for i in 0..5 {
            collector.collect_entry(test_entry(LogSource::Application, "Info", i));
        }
        assert_eq!(collector.entry_count(), 3);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = LogCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_get_entries_by_level_and_event_id() {
        let mut collector = LogCollector::new(test_bus());
        collector.collect_entry(test_entry(LogSource::Security, "Error", 4625));
        collector.collect_entry(test_entry(LogSource::Security, "Info", 4624));
        collector.collect_entry(test_entry(LogSource::Security, "Error", 1102));
        assert_eq!(collector.get_entries_by_level("Error").len(), 2);
        assert_eq!(collector.get_entries_by_event_id(4625).len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut collector = LogCollector::new(test_bus());
        collector.collect_entry(test_entry(LogSource::Security, "Info", 1));
        assert_eq!(collector.entry_count(), 1);
        collector.clear();
        assert_eq!(collector.entry_count(), 0);
    }

    #[test]
    fn test_source_counts() {
        let mut collector = LogCollector::new(test_bus());
        collector.collect_entry(test_entry(LogSource::Security, "Info", 1));
        collector.collect_entry(test_entry(LogSource::Security, "Info", 2));
        collector.collect_entry(test_entry(LogSource::System, "Info", 3));
        let counts = collector.source_counts();
        assert_eq!(counts[&LogSource::Security], 2);
        assert_eq!(counts[&LogSource::System], 1);
    }
}
