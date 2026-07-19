pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::*;
use royalsecurity_core::bus::EventBus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonEvent {
    pub event_id: i32,
    pub process_id: u32,
    pub user: String,
    pub details: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SysmonCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("XML parse error: {0}")]
    XmlParseError(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

pub struct SysmonCollector {
    bus: Arc<EventBus>,
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<SysmonEvent>>>,
    #[allow(dead_code)]
    last_event_record_id: Arc<RwLock<u64>>,
}

impl SysmonCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus: Arc::new(bus),
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            last_event_record_id: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), SysmonCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("Sysmon collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), SysmonCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("Sysmon collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub fn parse_event(xml: &str) -> Option<SysmonEvent> {
        let mut event_id = None;
        let mut process_id = None;
        let mut user = None;
        let mut details = HashMap::new();

        let trimmed = xml.trim();
        if trimmed.is_empty() {
            return None;
        }

        for line in trimmed.lines() {
            let line = line.trim();
            if line.starts_with("<EventID>") && line.ends_with("</EventID>") {
                let val = &line[9..line.len() - 10];
                event_id = val.parse::<i32>().ok();
            } else if line.starts_with("<ProcessId>") && line.ends_with("</ProcessId>") {
                let val = &line[11..line.len() - 12];
                process_id = val.parse::<u32>().ok();
            } else if line.starts_with("<User>") && line.ends_with("</User>") {
                user = Some(line[6..line.len() - 7].to_string());
            } else if line.starts_with("<Data Name=\"") {
                if let Some(name_end) = line.find("\">") {
                    let name = &line[12..name_end];
                    let value_end = line.find("</Data>");
                    if let Some(ve) = value_end {
                        let value = &line[name_end + 2..ve];
                        details.insert(name.to_string(), value.to_string());
                    }
                }
            }
        }

        let event_id = event_id?;
        let process_id = process_id.unwrap_or(0);
        let user = user.unwrap_or_default();

        Some(SysmonEvent {
            event_id,
            process_id,
            user,
            details,
            timestamp: Utc::now(),
        })
    }

    pub async fn capture_event(&self, event: SysmonEvent) -> std::result::Result<(), SysmonCollectorError> {
        if !*self.running.read().await {
            return Err(SysmonCollectorError::NotStarted);
        }
        debug!(
            event_id = event.event_id,
            pid = event.process_id,
            user = %event.user,
            "Captured Sysmon event"
        );
        self.publish_to_bus(&event);
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    fn publish_to_bus(&self, sysmon_event: &SysmonEvent) {
        let security_event = match sysmon_event.event_id {
            1 => {
                let path = sysmon_event.details.get("Image").cloned().unwrap_or_default();
                let cmd = sysmon_event.details.get("CommandLine").cloned().unwrap_or_default();
                SecurityEvent::Process(ProcessInfo {
                    pid: sysmon_event.process_id,
                    ppid: sysmon_event.details.get("ParentProcessId")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0),
                    name: path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string(),
                    path,
                    command_line: cmd,
                    user: sysmon_event.user.clone(),
                    hash_sha256: sysmon_event.details.get("Hashes")
                        .and_then(|h| h.strip_prefix("SHA256="))
                        .map(|s| s.to_string()),
                    integrity_level: sysmon_event.details.get("IntegrityLevel").cloned(),
                    timestamp: sysmon_event.timestamp,
                })
            }
            3 => {
                let src_ip = sysmon_event.details.get("SourceIp").and_then(|s| s.parse().ok());
                let dst_ip = sysmon_event.details.get("DestinationIp").and_then(|s| s.parse().ok());
                SecurityEvent::Network(NetworkEvent {
                    src_ip,
                    dst_ip,
                    src_port: sysmon_event.details.get("SourcePort")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0),
                    dst_port: sysmon_event.details.get("DestinationPort")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0),
                    protocol: Protocol::Tcp,
                    process_name: sysmon_event.details.get("Image").cloned(),
                    process_pid: Some(sysmon_event.process_id),
                    ..NetworkEvent::default()
                })
            }
            11 => {
                let path = sysmon_event.details.get("TargetFilename").cloned().unwrap_or_default();
                SecurityEvent::File(FileEvent {
                    path,
                    action: FileAction::Created,
                    timestamp: sysmon_event.timestamp,
                    ..FileEvent::default()
                })
            }
            13 => {
                let key = sysmon_event.details.get("TargetObject").cloned().unwrap_or_default();
                SecurityEvent::Registry(RegistryEvent {
                    key_path: key,
                    value_name: sysmon_event.details.get("Details").cloned(),
                    action: RegistryAction::Modified,
                    timestamp: sysmon_event.timestamp,
                    ..RegistryEvent::default()
                })
            }
            _ => {
                SecurityEvent::Process(ProcessInfo {
                    pid: sysmon_event.process_id,
                    name: format!("sysmon-event-{}", sysmon_event.event_id),
                    user: sysmon_event.user.clone(),
                    timestamp: sysmon_event.timestamp,
                    ..ProcessInfo::default()
                })
            }
        };

        if let Err(e) = self.bus.publish(security_event) {
            warn!("Failed to publish Sysmon event to bus: {}", e);
        }
    }

    #[cfg(target_os = "windows")]
    pub fn poll_real_events(&self) -> u32 {
        use windows::core::PCWSTR;

        let mut count = 0u32;
        unsafe {
            let path_wide: Vec<u16> = "Microsoft-Windows-Sysmon/Operational"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let result_set = match EvtQuery(
                EVT_HANDLE(0),
                PCWSTR(path_wide.as_ptr()),
                PCWSTR::null(),
                0x0001,
            ) {
                Ok(h) if h.0 != 0 => h,
                _ => return 0,
            };

            let mut event_handles: Vec<isize> = vec![0isize; 64];
            let mut returned = 0u32;

            while EvtNext(result_set, &mut event_handles, 100, 0, &mut returned).is_ok() && returned > 0 {
                for i in 0..returned as usize {
                    let evt_handle = EVT_HANDLE(event_handles[i]);
                    if evt_handle.0 == 0 {
                        continue;
                    }

                    let mut used = 0u32;
                    let mut prop_count = 0u32;

                    if EvtRender(
                        EVT_HANDLE(0),
                        evt_handle,
                        0x00000001,
                        0,
                        None,
                        &mut used,
                        &mut prop_count,
                    ).is_err() {
                        let mut buf = vec![0u8; used as usize];
                        if EvtRender(
                            EVT_HANDLE(0),
                            evt_handle,
                            0x00000001,
                            used,
                            Some(buf.as_mut_ptr() as *mut _),
                            &mut used,
                            &mut prop_count,
                        ).is_ok() {
                            if let Ok(xml) = std::string::String::from_utf8(buf) {
                                if let Some(event) = Self::parse_event(&xml) {
                                    self.publish_to_bus(&event);
                                    let mut events = self.events.blocking_write();
                                    events.push(event);
                                    count += 1;
                                }
                            }
                        }
                    }

                    let _ = EvtClose(evt_handle);
                }
            }

            let _ = EvtClose(result_set);
        }
        count
    }

    pub async fn get_events(&self) -> Vec<SysmonEvent> {
        self.events.read().await.clone()
    }

    pub async fn get_events_by_id(&self, event_id: i32) -> Vec<SysmonEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.event_id == event_id)
            .cloned()
            .collect()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        debug!("Sysmon collector cleared all events");
    }
}

impl Default for SysmonCollector {
    fn default() -> Self {
        Self::new(EventBus::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_xml() {
        let xml = r#"<EventID>1</EventID>
<ProcessId>1234</ProcessId>
<User>SYSTEM</User>
<Data Name="Image">C:\Windows\System32\cmd.exe</Data>
<Data Name="CommandLine">cmd.exe /c whoami</Data>"#;

        let event = SysmonCollector::parse_event(xml).unwrap();
        assert_eq!(event.event_id, 1);
        assert_eq!(event.process_id, 1234);
        assert_eq!(event.user, "SYSTEM");
        assert_eq!(
            event.details.get("Image").unwrap(),
            "C:\\Windows\\System32\\cmd.exe"
        );
        assert_eq!(
            event.details.get("CommandLine").unwrap(),
            "cmd.exe /c whoami"
        );
    }

    #[test]
    fn test_parse_empty_xml() {
        assert!(SysmonCollector::parse_event("").is_none());
        assert!(SysmonCollector::parse_event("   ").is_none());
    }

    #[test]
    fn test_parse_missing_event_id() {
        let xml = r#"<ProcessId>1234</ProcessId>
<User>SYSTEM</User>"#;
        assert!(SysmonCollector::parse_event(xml).is_none());
    }

    #[test]
    fn test_parse_missing_optional_fields() {
        let xml = "<EventID>3</EventID>";
        let event = SysmonCollector::parse_event(xml).unwrap();
        assert_eq!(event.event_id, 3);
        assert_eq!(event.process_id, 0);
        assert!(event.user.is_empty());
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = SysmonCollector::new(EventBus::new());
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = SysmonCollector::new(EventBus::new());
        let event = SysmonEvent {
            event_id: 1,
            process_id: 100,
            user: "test".into(),
            details: HashMap::new(),
            timestamp: Utc::now(),
        };
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_and_count() {
        let collector = SysmonCollector::new(EventBus::new());
        collector.start().await.unwrap();
        for i in 0..5 {
            let event = SysmonEvent {
                event_id: i,
                process_id: i as u32,
                user: format!("user{}", i),
                details: HashMap::new(),
                timestamp: Utc::now(),
            };
            collector.capture_event(event).await.unwrap();
        }
        assert_eq!(collector.event_count().await, 5);
    }

    #[tokio::test]
    async fn test_get_events_by_id() {
        let collector = SysmonCollector::new(EventBus::new());
        collector.start().await.unwrap();
        for id in [1, 2, 1, 3, 1] {
            let event = SysmonEvent {
                event_id: id,
                process_id: 100,
                user: "test".into(),
                details: HashMap::new(),
                timestamp: Utc::now(),
            };
            collector.capture_event(event).await.unwrap();
        }
        let id1_events = collector.get_events_by_id(1).await;
        assert_eq!(id1_events.len(), 3);
        let id2_events = collector.get_events_by_id(2).await;
        assert_eq!(id2_events.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = SysmonCollector::new(EventBus::new());
        collector.start().await.unwrap();
        let event = SysmonEvent {
            event_id: 1,
            process_id: 100,
            user: "test".into(),
            details: HashMap::new(),
            timestamp: Utc::now(),
        };
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }
}
