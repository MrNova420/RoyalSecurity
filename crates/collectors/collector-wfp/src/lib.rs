pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WfpAction {
    Permit,
    Block,
    Callout,
    Continue,
    Drop,
}

impl std::fmt::Display for WfpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfpAction::Permit => write!(f, "Permit"),
            WfpAction::Block => write!(f, "Block"),
            WfpAction::Callout => write!(f, "Callout"),
            WfpAction::Continue => write!(f, "Continue"),
            WfpAction::Drop => write!(f, "Drop"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WfpDirection {
    Inbound,
    Outbound,
}

impl std::fmt::Display for WfpDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfpDirection::Inbound => write!(f, "Inbound"),
            WfpDirection::Outbound => write!(f, "Outbound"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpEvent {
    pub filter_id: u32,
    pub action: WfpAction,
    pub direction: WfpDirection,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum WfpCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid WFP event: {0}")]
    InvalidEvent(String),
    #[cfg(target_os = "windows")]
    #[error("WFP engine error: {0}")]
    EngineError(String),
    #[cfg(not(target_os = "windows"))]
    #[error("WFP not supported on this platform")]
    NotSupported,
}

pub struct WfpCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<WfpEvent>>>,
    #[cfg(target_os = "windows")]
    engine_handle: Arc<RwLock<Option<windows::Win32::Foundation::HANDLE>>>,
}

impl WfpCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            #[cfg(target_os = "windows")]
            engine_handle: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), WfpCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("WFP collector started");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn start_wfp_session(
        &self,
    ) -> std::result::Result<(), WfpCollectorError> {
        let handle = open_wfp_engine()
            .map_err(WfpCollectorError::EngineError)?;
        let mut guard = self.engine_handle.write().await;
        *guard = Some(handle);
        info!("WFP engine session opened");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn start_wfp_session(
        &self,
    ) -> std::result::Result<(), WfpCollectorError> {
        warn!("WFP engine sessions are not supported on this platform");
        Err(WfpCollectorError::NotSupported)
    }

    pub async fn stop(&self) -> std::result::Result<(), WfpCollectorError> {
        #[cfg(target_os = "windows")]
        {
            let mut guard = self.engine_handle.write().await;
            if let Some(handle) = guard.take() {
                unsafe {
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(handle);
                }
                info!("WFP engine session closed");
            }
        }
        let mut running = self.running.write().await;
        *running = false;
        info!("WFP collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_event(&self, event: WfpEvent) -> std::result::Result<(), WfpCollectorError> {
        if !*self.running.read().await {
            return Err(WfpCollectorError::NotStarted.into());
        }
        if event.process_name.is_empty() {
            return Err(WfpCollectorError::InvalidEvent(
                "Empty process name".into(),
            )
            .into());
        }
        debug!(
            filter_id = event.filter_id,
            action = %event.action,
            process = %event.process_name,
            "Captured WFP event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub async fn poll_net_events(&self) -> std::result::Result<Vec<WfpEvent>, WfpCollectorError> {
        let guard = self.engine_handle.read().await;
        let handle = guard.ok_or(WfpCollectorError::NotStarted)?;
        let raw_events = enumerate_net_events(handle)
            .map_err(WfpCollectorError::EngineError)?;
        let mut wfp_events = Vec::new();
        for raw in &raw_events {
            if let Some(evt) = net_event_to_wfp_event(raw) {
                wfp_events.push(evt);
            }
        }
        Ok(wfp_events)
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn poll_net_events(&self) -> std::result::Result<Vec<WfpEvent>, WfpCollectorError> {
        Err(WfpCollectorError::NotSupported)
    }

    #[cfg(target_os = "windows")]
    pub async fn get_active_filters(&self) -> std::result::Result<Vec<WfpFilterInfo>, WfpCollectorError> {
        let guard = self.engine_handle.read().await;
        let handle = guard.ok_or(WfpCollectorError::NotStarted)?;
        enumerate_filters(handle)
            .map_err(WfpCollectorError::EngineError)
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn get_active_filters(&self) -> std::result::Result<Vec<WfpFilterInfo>, WfpCollectorError> {
        Err(WfpCollectorError::NotSupported)
    }

    pub async fn get_events(&self) -> Vec<WfpEvent> {
        self.events.read().await.clone()
    }

    pub async fn get_blocked_events(&self) -> Vec<WfpEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.action == WfpAction::Block || e.action == WfpAction::Drop)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_action(&self, action: WfpAction) -> Vec<WfpEvent> {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.action == action)
            .cloned()
            .collect()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        debug!("WFP collector cleared all events");
    }
}

impl Default for WfpCollector {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: engine_handle is only accessed under RwLock across awaits and never
// used concurrently from multiple threads. The HANDLE is always properly closed.
unsafe impl Send for WfpCollector {}
unsafe impl Sync for WfpCollector {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpFilterInfo {
    pub filter_id: u64,
    pub display_name: String,
    pub action: WfpAction,
    pub weight: Option<i64>,
}

#[cfg(target_os = "windows")]
mod wfp_internal {
    use super::*;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows::core::PCWSTR;

    const MAX_ENUM_EVENTS: u32 = 100;
    const MAX_ENUM_FILTERS: u32 = 256;

    const FWPM_NET_EVENT_FLAG_INBOUND: u32 = 0x00000001;
    const FWPM_NET_EVENT_FLAG_OUTBOUND: u32 = 0x00000002;

    const FWP_IP_VERSION_V4: i32 = 0;

    const FWP_ACTION_BLOCK: u32 = 0x00000000;
    const FWP_ACTION_PERMIT: u32 = 0x00000001;
    const FWP_ACTION_CALLOUT_TERMINATING: u32 = 0x00000002;
    const FWP_ACTION_CALLOUT_INSPECTION: u32 = 0x00000003;
    const FWP_ACTION_CALLOUT_CONTINUE: u32 = 0x00000004;

    pub fn open_wfp_engine() -> Result<HANDLE, String> {
        unsafe {
            let mut engine_handle = HANDLE::default();
            let result = FwpmEngineOpen0(
                PCWSTR::null(),
                10,
                None,
                None,
                &mut engine_handle,
            );
            if result == 0 {
                Ok(engine_handle)
            } else {
                Err(format!(
                    "FwpmEngineOpen0 failed with error code: 0x{:08X}",
                    result
                ))
            }
        }
    }

    #[allow(dead_code)]
    pub fn close_wfp_engine(handle: HANDLE) {
        unsafe {
            FwpmEngineClose0(handle);
        }
    }

    pub fn enumerate_net_events(
        engine_handle: HANDLE,
    ) -> Result<Vec<FWPM_NET_EVENT0>, String> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            let result = FwpmNetEventCreateEnumHandle0(
                engine_handle,
                None,
                &mut enum_handle,
            );
            if result != 0 {
                return Err(format!(
                    "FwpmNetEventCreateEnumHandle0 failed: 0x{:08X}",
                    result
                ));
            }

            let mut events_ptr: *mut *mut FWPM_NET_EVENT0 = std::ptr::null_mut();
            let mut num_returned: u32 = 0;
            let result = FwpmNetEventEnum0(
                engine_handle,
                enum_handle,
                MAX_ENUM_EVENTS,
                &mut events_ptr,
                &mut num_returned,
            );

            if result != 0 {
                FwpmNetEventDestroyEnumHandle0(engine_handle, enum_handle);
                return Err(format!(
                    "FwpmNetEventEnum0 failed: 0x{:08X}",
                    result
                ));
            }

            let mut events = Vec::new();
            if !events_ptr.is_null() && num_returned > 0 {
                let slice = std::slice::from_raw_parts(events_ptr, num_returned as usize);
                for event_ptr in slice {
                    if !event_ptr.is_null() {
                        events.push(**event_ptr);
                    }
                }
                FwpmFreeMemory0(&mut events_ptr as *mut _ as _);
            }

            FwpmNetEventDestroyEnumHandle0(engine_handle, enum_handle);
            Ok(events)
        }
    }

    pub fn enumerate_filters(
        engine_handle: HANDLE,
    ) -> Result<Vec<WfpFilterInfo>, String> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            let result = FwpmFilterCreateEnumHandle0(
                engine_handle,
                None,
                &mut enum_handle,
            );
            if result != 0 {
                return Err(format!(
                    "FwpmFilterCreateEnumHandle0 failed: 0x{:08X}",
                    result
                ));
            }

            let mut filters_ptr: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut num_returned: u32 = 0;
            let result = FwpmFilterEnum0(
                engine_handle,
                enum_handle,
                MAX_ENUM_FILTERS,
                &mut filters_ptr,
                &mut num_returned,
            );

            if result != 0 {
                FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
                return Err(format!(
                    "FwpmFilterEnum0 failed: 0x{:08X}",
                    result
                ));
            }

            let mut filter_infos = Vec::new();
            if !filters_ptr.is_null() && num_returned > 0 {
                let slice = std::slice::from_raw_parts(filters_ptr, num_returned as usize);
                for filter_ptr in slice {
                    if !filter_ptr.is_null() {
                        let f = &**filter_ptr;
                        let display_name = extract_display_data(&f.displayData);
                        let action = action_from_wfp_action_type(f.action.r#type.0);
                        filter_infos.push(WfpFilterInfo {
                            filter_id: f.filterId,
                            display_name,
                            action,
                            weight: extract_weight_value(&f.weight),
                        });
                    }
                }
                FwpmFreeMemory0(&mut filters_ptr as *mut _ as _);
            }

            FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
            Ok(filter_infos)
        }
    }

    fn extract_display_data(display_data: &FWPM_DISPLAY_DATA0) -> String {
        unsafe {
            if !display_data.name.is_null() {
                PCWSTR(display_data.name.0).to_string().unwrap_or_default()
            } else {
                String::new()
            }
        }
    }

    fn extract_weight_value(weight: &FWP_VALUE0) -> Option<i64> {
        unsafe {
            match weight.r#type.0 {
                4 => Some(weight.Anonymous.uint64 as i64),
                8 => Some(*weight.Anonymous.int64),
                3 => Some(weight.Anonymous.uint32 as i64),
                7 => Some(weight.Anonymous.int32 as i64),
                _ => None,
            }
        }
    }

    pub fn action_from_wfp_action_type(action_type: u32) -> WfpAction {
        match action_type {
            FWP_ACTION_BLOCK => WfpAction::Block,
            FWP_ACTION_PERMIT => WfpAction::Permit,
            FWP_ACTION_CALLOUT_TERMINATING | FWP_ACTION_CALLOUT_INSPECTION => WfpAction::Callout,
            FWP_ACTION_CALLOUT_CONTINUE => WfpAction::Continue,
            _ => WfpAction::Drop,
        }
    }

    pub fn protocol_from_number(proto: u8) -> String {
        match proto {
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            47 => "GRE".to_string(),
            50 => "ESP".to_string(),
            51 => "AH".to_string(),
            58 => "ICMPv6".to_string(),
            _ => format!("Proto({})", proto),
        }
    }

    pub fn ipv4_to_string(addr: u32) -> String {
        let b = addr.to_le_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }

    pub fn net_event_to_wfp_event(event: &FWPM_NET_EVENT0) -> Option<WfpEvent> {
        let header = &event.header;

        let (local_addr, remote_addr) = unsafe {
            if header.ipVersion.0 == FWP_IP_VERSION_V4 {
                let local = ipv4_to_string(header.Anonymous1.localAddrV4);
                let remote = ipv4_to_string(header.Anonymous2.remoteAddrV4);
                (local, remote)
            } else {
                ("IPv6".to_string(), "IPv6".to_string())
            }
        };

        let direction = if header.flags & FWPM_NET_EVENT_FLAG_INBOUND != 0 {
            WfpDirection::Inbound
        } else if header.flags & FWPM_NET_EVENT_FLAG_OUTBOUND != 0 {
            WfpDirection::Outbound
        } else {
            WfpDirection::Outbound
        };

        let event_type = event.r#type.0;

        let action = match event_type {
            3 => WfpAction::Drop,
            4 | 5 | 6 => WfpAction::Drop,
            _ => WfpAction::Permit,
        };

        let filter_id = unsafe {
            match event_type {
                3 => {
                    let drop = event.Anonymous.classifyDrop;
                    if !drop.is_null() { (*drop).filterId as u32 } else { 0 }
                }
                _ => 0,
            }
        };

        let process_name = unsafe {
            if !header.appId.data.is_null() && header.appId.size > 0 {
                let bytes = std::slice::from_raw_parts(
                    header.appId.data as *const u8,
                    (header.appId.size as usize).min(512),
                );
                String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string()
            } else {
                String::from("unknown")
            }
        };

        let timestamp = {
            let ft = header.timeStamp;
            let filetime = ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64);
            let unix_time = (filetime - 116444736000000000) / 10000000;
            DateTime::from_timestamp(unix_time, 0).unwrap_or_else(Utc::now)
        };

        Some(WfpEvent {
            filter_id,
            action,
            direction,
            protocol: protocol_from_number(header.ipProtocol),
            local_addr,
            remote_addr,
            local_port: header.localPort,
            remote_port: header.remotePort,
            process_name,
            pid: 0,
            timestamp,
        })
    }

    #[allow(dead_code)]
    pub struct WfpEngineGuard {
        handle: HANDLE,
    }

    #[allow(dead_code)]
    impl WfpEngineGuard {
        pub fn open() -> Result<Self, String> {
            let handle = open_wfp_engine()?;
            Ok(Self { handle })
        }

        pub fn handle(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for WfpEngineGuard {
        fn drop(&mut self) {
            close_wfp_engine(self.handle);
        }
    }

    unsafe impl Send for WfpEngineGuard {}
    unsafe impl Sync for WfpEngineGuard {}
}

pub fn protocol_from_number(proto: u8) -> String {
    #[cfg(target_os = "windows")]
    {
        wfp_internal::protocol_from_number(proto)
    }
    #[cfg(not(target_os = "windows"))]
    {
        match proto {
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            47 => "GRE".to_string(),
            50 => "ESP".to_string(),
            51 => "AH".to_string(),
            58 => "ICMPv6".to_string(),
            _ => format!("Proto({})", proto),
        }
    }
}

#[cfg(target_os = "windows")]
fn open_wfp_engine() -> Result<windows::Win32::Foundation::HANDLE, String> {
    wfp_internal::open_wfp_engine()
}

#[cfg(target_os = "windows")]
fn enumerate_net_events(
    engine_handle: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT0>, String> {
    wfp_internal::enumerate_net_events(engine_handle)
}

#[cfg(target_os = "windows")]
fn enumerate_filters(
    engine_handle: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<WfpFilterInfo>, String> {
    wfp_internal::enumerate_filters(engine_handle)
}

#[cfg(target_os = "windows")]
fn net_event_to_wfp_event(
    event: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT0,
) -> Option<WfpEvent> {
    wfp_internal::net_event_to_wfp_event(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(action: WfpAction, process: &str) -> WfpEvent {
        WfpEvent {
            filter_id: 100,
            action,
            direction: WfpDirection::Outbound,
            protocol: "TCP".to_string(),
            local_addr: "192.168.1.1".to_string(),
            remote_addr: "10.0.0.1".to_string(),
            local_port: 443,
            remote_port: 8080,
            process_name: process.to_string(),
            pid: 4321,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = WfpCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = WfpCollector::new();
        let event = make_event(WfpAction::Permit, "chrome.exe");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WfpAction::Permit, "chrome.exe");
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_process() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WfpAction::Permit, "");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_get_blocked_events() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WfpAction::Permit, "a.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Block, "b.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Drop, "c.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Permit, "d.exe"))
            .await
            .unwrap();

        let blocked = collector.get_blocked_events().await;
        assert_eq!(blocked.len(), 2);
    }

    #[tokio::test]
    async fn test_get_events_by_action() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WfpAction::Block, "a.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Block, "b.exe"))
            .await
            .unwrap();
        collector
            .capture_event(make_event(WfpAction::Callout, "c.exe"))
            .await
            .unwrap();

        let blocks = collector.get_events_by_action(WfpAction::Block).await;
        assert_eq!(blocks.len(), 2);
        let callouts = collector.get_events_by_action(WfpAction::Callout).await;
        assert_eq!(callouts.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WfpAction::Permit, "test.exe"))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }

    #[tokio::test]
    async fn test_direction_tracking() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        let mut inbound = make_event(WfpAction::Permit, "server.exe");
        inbound.direction = WfpDirection::Inbound;
        collector.capture_event(inbound).await.unwrap();
        let events = collector.get_events().await;
        assert_eq!(events[0].direction, WfpDirection::Inbound);
    }

    #[test]
    fn test_protocol_from_number() {
        assert_eq!(protocol_from_number(1), "ICMP");
        assert_eq!(protocol_from_number(6), "TCP");
        assert_eq!(protocol_from_number(17), "UDP");
        assert_eq!(protocol_from_number(47), "GRE");
        assert_eq!(protocol_from_number(50), "ESP");
        assert_eq!(protocol_from_number(51), "AH");
        assert_eq!(protocol_from_number(58), "ICMPv6");
        assert_eq!(protocol_from_number(99), "Proto(99)");
    }

    #[test]
    fn test_action_display() {
        assert_eq!(WfpAction::Permit.to_string(), "Permit");
        assert_eq!(WfpAction::Block.to_string(), "Block");
        assert_eq!(WfpAction::Callout.to_string(), "Callout");
        assert_eq!(WfpAction::Continue.to_string(), "Continue");
        assert_eq!(WfpAction::Drop.to_string(), "Drop");
    }

    #[test]
    fn test_direction_display() {
        assert_eq!(WfpDirection::Inbound.to_string(), "Inbound");
        assert_eq!(WfpDirection::Outbound.to_string(), "Outbound");
    }

    #[test]
    fn test_wfp_event_serialization() {
        let event = make_event(WfpAction::Block, "malware.exe");
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: WfpEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.filter_id, event.filter_id);
        assert_eq!(deserialized.action, event.action);
        assert_eq!(deserialized.process_name, event.process_name);
    }

    #[test]
    fn test_wfp_filter_info_serialization() {
        let info = WfpFilterInfo {
            filter_id: 42,
            display_name: "Block Outbound".to_string(),
            action: WfpAction::Block,
            weight: Some(100),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: WfpFilterInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.filter_id, 42);
        assert_eq!(deserialized.action, WfpAction::Block);
    }

    #[tokio::test]
    async fn test_start_wfp_session_not_supported() {
        let _collector = WfpCollector::new();
        #[cfg(not(target_os = "windows"))]
        {
            let result = _collector.start_wfp_session().await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_poll_net_events_not_supported() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        #[cfg(not(target_os = "windows"))]
        {
            let result = collector.poll_net_events().await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_get_active_filters_not_supported() {
        let collector = WfpCollector::new();
        collector.start().await.unwrap();
        #[cfg(not(target_os = "windows"))]
        {
            let result = collector.get_active_filters().await;
            assert!(result.is_err());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_action_type_conversion() {
        use wfp_internal::action_from_wfp_action_type;
        assert_eq!(action_from_wfp_action_type(0), WfpAction::Block);
        assert_eq!(action_from_wfp_action_type(1), WfpAction::Permit);
        assert_eq!(action_from_wfp_action_type(2), WfpAction::Callout);
        assert_eq!(action_from_wfp_action_type(3), WfpAction::Callout);
        assert_eq!(action_from_wfp_action_type(4), WfpAction::Continue);
        assert_eq!(action_from_wfp_action_type(99), WfpAction::Drop);
    }

    #[test]
    fn test_event_count_after_multiple_captures() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let collector = WfpCollector::new();
            collector.start().await.unwrap();
            for i in 0..10 {
                let mut event = make_event(WfpAction::Permit, "test.exe");
                event.filter_id = i;
                collector.capture_event(event).await.unwrap();
            }
            assert_eq!(collector.event_count().await, 10);
            collector.clear().await;
            assert_eq!(collector.event_count().await, 0);
        });
    }
}
