pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_core::bus::EventBus;
use std::error::Error;
use std::time::Instant;
use tracing::{info, warn};
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

const HTTP_ETW_REAL_TIME_MODE: u32 = 0x00000100;
const HTTP_ETW_PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const HTTP_ETW_PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x01000000;
const WINHTTP_PROVIDER_GUID: &str = "5d963abb-c097-4722-81d5-615f78e1d772";

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Etw::*;
#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, PWSTR, GUID};

#[cfg(target_os = "windows")]
struct HttpEtwContext {
    shared_events: Arc<Mutex<Vec<HttpEvent>>>,
    events_processed: AtomicU64,
    errors: AtomicU64,
}

#[cfg(target_os = "windows")]
struct HttpEtwInner {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    ctx: *mut HttpEtwContext,
    properties_buffer: Vec<u8>,
}

unsafe impl Send for HttpEtwInner {}
unsafe impl Sync for HttpEtwInner {}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("HTTP collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpEvent {
    pub method: String,
    pub url: String,
    pub status_code: u16,
    pub content_type: String,
    pub process_name: String,
    pub timestamp: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub struct HttpCollector {
    _bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    requests: Vec<HttpEvent>,
    max_requests: usize,
    #[cfg(target_os = "windows")]
    etw_inner: Option<HttpEtwInner>,
    #[cfg(target_os = "windows")]
    etw_shared_events: Option<Arc<Mutex<Vec<HttpEvent>>>>,
    #[cfg(target_os = "windows")]
    etw_events_count: u64,
}

impl HttpCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            requests: Vec::new(),
            max_requests: 100_000,
            #[cfg(target_os = "windows")]
            etw_inner: None,
            #[cfg(target_os = "windows")]
            etw_shared_events: None,
            #[cfg(target_os = "windows")]
            etw_events_count: 0,
        }
    }

    pub fn with_max_requests(bus: EventBus, max: usize) -> Self {
        Self {
            max_requests: max,
            ..Self::new(bus)
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), HttpError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("HTTP Collector started");
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), HttpError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "HTTP Collector stopped. Captured {} requests",
            self.requests.len()
        );
        Ok(())
    }

    pub fn capture_request(&mut self, event: HttpEvent) {
        if self.requests.len() >= self.max_requests {
            self.requests.remove(0);
        }
        self.requests.push(event);
    }

    pub fn get_requests(&self) -> Vec<&HttpEvent> {
        self.requests.iter().collect()
    }

    pub fn get_requests_by_process(&self, process: &str) -> Vec<&HttpEvent> {
        self.requests
            .iter()
            .filter(|r| r.process_name == process)
            .collect()
    }

    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    pub fn get_requests_by_method(&self, method: &str) -> Vec<&HttpEvent> {
        self.requests
            .iter()
            .filter(|r| r.method.eq_ignore_ascii_case(method))
            .collect()
    }

    pub fn get_requests_by_status(&self, status: u16) -> Vec<&HttpEvent> {
        self.requests.iter().filter(|r| r.status_code == status).collect()
    }

    pub fn get_requests_by_domain(&self, domain: &str) -> Vec<&HttpEvent> {
        self.requests
            .iter()
            .filter(|r| r.url.contains(domain))
            .collect()
    }

    pub fn total_bytes_sent(&self) -> u64 {
        self.requests.iter().map(|r| r.bytes_sent).sum()
    }

    pub fn total_bytes_received(&self) -> u64 {
        self.requests.iter().map(|r| r.bytes_received).sum()
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn clear(&mut self) {
        self.requests.clear();
    }

    pub fn set_max_requests(&mut self, max: usize) {
        self.max_requests = max;
    }

    #[cfg(target_os = "windows")]
    fn logger_name_wide_http() -> Vec<u16> {
        "RoyalsecurityHttpETW"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    #[cfg(target_os = "windows")]
    fn build_http_properties_buffer(logger_name: &[u16]) -> Vec<u8> {
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = logger_name.len() * 2;
        let buffer_size = properties_size + name_bytes + 64;
        let mut buffer = vec![0u8; buffer_size];

        unsafe {
            let props = &mut *(buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            props.Wnode.BufferSize = buffer_size as u32;
            props.Wnode.Flags = 0x00000001;
            props.BufferSize = 64;
            props.MinimumBuffers = 8;
            props.MaximumBuffers = 128;
            props.LogFileMode = HTTP_ETW_REAL_TIME_MODE;
            props.LoggerNameOffset = properties_size as u32;
            props.LogFileNameOffset = 0;
            std::ptr::copy_nonoverlapping(
                logger_name.as_ptr(),
                buffer.as_mut_ptr().add(properties_size) as *mut u16,
                logger_name.len(),
            );
        }
        buffer
    }

    #[cfg(target_os = "windows")]
    fn parse_http_etw_event(user_data: &[u8]) -> Option<HttpEvent> {
        if user_data.len() < 8 {
            return None;
        }

        let event_id = u16::from_le_bytes([user_data[0], user_data[1]]);
        let _version = user_data[2];

        let mut method = String::new();
        let mut url = String::new();
        let mut status_code: u16 = 0;
        let mut bytes_sent: u64 = 0;
        let mut bytes_received: u64 = 0;

        match event_id {
            1 => {
                if user_data.len() >= 16 {
                    let conn_id = u64::from_le_bytes(user_data[4..12].try_into().ok()?);
                    let _addr = u32::from_le_bytes(user_data[12..16].try_into().ok()?);
                    url = format!("conn://{}", conn_id);
                    method = "CONNECT".into();
                }
            }
            2 => {
                if user_data.len() >= 24 {
                    let conn_id = u64::from_le_bytes(user_data[4..12].try_into().ok()?);
                    status_code = u16::from_le_bytes(user_data[12..14].try_into().ok()?);
                    let verb_id = u16::from_le_bytes(user_data[14..16].try_into().ok()?);
                    method = match verb_id {
                        1 => "GET",
                        2 => "PUT",
                        3 => "POST",
                        4 => "DELETE",
                        5 => "HEAD",
                        _ => "OTHER",
                    }
                    .into();
                    bytes_sent = u64::from_le_bytes(user_data[16..24].try_into().ok()?);
                    url = format!("http://conn/{}", conn_id);
                }
            }
            3 => {
                if user_data.len() >= 20 {
                    status_code = u16::from_le_bytes(user_data[4..6].try_into().ok()?);
                    bytes_received = u64::from_le_bytes(user_data[8..16].try_into().ok()?);
                    url = "http://response".into();
                    method = "RESPONSE".into();
                }
            }
            _ => return None,
        }

        if method.is_empty() && url.is_empty() {
            return None;
        }

        Some(HttpEvent {
            method,
            url,
            status_code,
            content_type: String::new(),
            process_name: String::new(),
            timestamp: Utc::now(),
            bytes_sent,
            bytes_received,
        })
    }

    #[cfg(target_os = "windows")]
    unsafe extern "system" fn http_etw_event_callback(event_record: *mut EVENT_RECORD) {
        if event_record.is_null() {
            return;
        }
        let record = &*event_record;
        if record.UserContext.is_null() || record.UserData.is_null() || record.UserDataLength == 0 {
            return;
        }
        let ctx = &*(record.UserContext as *const HttpEtwContext);
        let user_data =
            std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize);

        match Self::parse_http_etw_event(user_data) {
            Some(http_event) => {
                ctx.events_processed.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut events) = ctx.shared_events.lock() {
                    events.push(http_event);
                } else {
                    ctx.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {}
        }
    }

    pub fn sync_etw_events(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let drained: Vec<HttpEvent> = if let Some(ref shared) = self.etw_shared_events {
                shared
                    .lock()
                    .map(|mut incoming| incoming.drain(..).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let count = drained.len() as u64;
            for event in drained {
                self.capture_request(event);
            }
            self.etw_events_count += count;
        }
    }

    pub fn etw_events_captured(&self) -> u64 {
        #[cfg(target_os = "windows")]
        {
            self.etw_events_count
        }
        #[cfg(not(target_os = "windows"))]
        {
            0
        }
    }

    #[cfg(target_os = "windows")]
    pub fn enable_http_etw_tracing(&mut self) -> Result<(), String> {
        let logger_name = Self::logger_name_wide_http();
        let mut buffer = Self::build_http_properties_buffer(&logger_name);
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_pcwstr =
            unsafe { PCWSTR(buffer.as_mut_ptr().add(properties_size) as *const u16) };

        let shared_events = Arc::new(Mutex::new(Vec::new()));
        let shared_events_for_ctx = Arc::clone(&shared_events);

        unsafe {
            let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
            let result = StartTraceW(
                &mut session_handle,
                name_pcwstr,
                buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            );
            if result.0 != 0 && result.0 != 183 {
                return Err(format!(
                    "StartTraceW failed: WIN32_ERROR({})",
                    result.0
                ));
            }
            info!(handle = ?session_handle, "HTTP ETW trace session started");

            let guid = GUID::from(WINHTTP_PROVIDER_GUID);
            let result =
                EnableTraceEx2(session_handle, &guid, 1, 4, 0, 0, 0, None);
            if result.0 != 0 {
                warn!(
                    provider = "Microsoft-Windows-WinHttp",
                    error = result.0,
                    "Failed to enable WinHttp ETW provider"
                );
            } else {
                info!(
                    provider = "Microsoft-Windows-WinHttp",
                    "WinHttp ETW provider enabled"
                );
            }

            let ctx = Box::into_raw(Box::new(HttpEtwContext {
                shared_events: shared_events_for_ctx,
                events_processed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
            }));

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName =
                PWSTR(buffer.as_mut_ptr().add(properties_size) as *mut u16);
            logfile.Anonymous1 = EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: HTTP_ETW_PROCESS_TRACE_MODE_REAL_TIME
                    | HTTP_ETW_PROCESS_TRACE_MODE_EVENT_RECORD,
            };
            logfile.Anonymous2 = EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(Self::http_etw_event_callback),
            };
            logfile.Context = ctx as *mut _;

            let trace_handle = OpenTraceW(&mut logfile);
            if trace_handle.Value == 0 || trace_handle.Value == u64::MAX {
                let _ = Box::from_raw(ctx);
                return Err(format!(
                    "OpenTraceW failed: INVALID_HANDLE (value={})",
                    trace_handle.Value
                ));
            }
            info!(handle = ?trace_handle, "HTTP ETW trace opened");

            self.etw_inner = Some(HttpEtwInner {
                session_handle,
                trace_handle,
                ctx,
                properties_buffer: buffer,
            });
            self.etw_shared_events = Some(shared_events);
            self.start_time = Some(Instant::now());
            self.status = ModuleStatus::Running;
            info!("HTTP ETW tracing enabled via Microsoft-Windows-WinHttp");
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enable_http_etw_tracing(&mut self) -> Result<(), String> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("HTTP ETW tracing enabled (stub on non-Windows)");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn disable_http_etw_tracing(&mut self) -> Result<(), String> {
        self.sync_etw_events();

        if let Some(inner) = self.etw_inner.take() {
            unsafe {
                let logger_name = Self::logger_name_wide_http();
                let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
                let name_bytes = logger_name.len() * 2;
                let buffer_size = properties_size + name_bytes + 64;
                let mut stop_buffer = vec![0u8; buffer_size];
                {
                    let props =
                        &mut *(stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                    props.Wnode.BufferSize = buffer_size as u32;
                    props.LoggerNameOffset = properties_size as u32;
                }
                std::ptr::copy_nonoverlapping(
                    logger_name.as_ptr(),
                    stop_buffer.as_mut_ptr().add(properties_size) as *mut u16,
                    logger_name.len(),
                );

                let name_pcwstr =
                    PCWSTR(stop_buffer.as_mut_ptr().add(properties_size) as *const u16);

                let result = ControlTraceW(
                    inner.session_handle,
                    name_pcwstr,
                    stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                );
                info!(result = ?result, "HTTP ETW trace session stop requested");

                if inner.trace_handle.Value != 0 && inner.trace_handle.Value != u64::MAX {
                    let _ = CloseTrace(inner.trace_handle);
                }

                let _ = Box::from_raw(inner.ctx);
            }
        }

        self.etw_shared_events = None;
        self.status = ModuleStatus::Stopped;
        info!(
            "HTTP ETW tracing disabled. Captured {} requests ({} from ETW)",
            self.requests.len(),
            self.etw_events_count
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn disable_http_etw_tracing(&mut self) -> Result<(), String> {
        self.status = ModuleStatus::Stopped;
        info!(
            "HTTP ETW tracing disabled (stub on non-Windows). Captured {} requests",
            self.requests.len()
        );
        Ok(())
    }
}

#[async_trait]
impl SecurityModule for HttpCollector {
    fn name(&self) -> &str {
        "HTTP Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors HTTP/HTTPS traffic metadata"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("HTTP Collector initialized");
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

    fn test_request(method: &str, url: &str, process: &str, status: u16) -> HttpEvent {
        HttpEvent {
            method: method.into(),
            url: url.into(),
            status_code: status,
            content_type: "text/html".into(),
            process_name: process.into(),
            timestamp: Utc::now(),
            bytes_sent: 1024,
            bytes_received: 4096,
        }
    }

    #[test]
    fn test_new_collector() {
        let collector = HttpCollector::new(test_bus());
        assert_eq!(collector.request_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_capture_and_retrieve() {
        let mut collector = HttpCollector::new(test_bus());
        collector.capture_request(test_request("GET", "https://example.com", "chrome.exe", 200));
        collector.capture_request(test_request("POST", "https://api.test.com", "curl.exe", 201));
        assert_eq!(collector.request_count(), 2);
        assert_eq!(collector.get_requests().len(), 2);
    }

    #[test]
    fn test_get_requests_by_process() {
        let mut collector = HttpCollector::new(test_bus());
        collector.capture_request(test_request("GET", "https://a.com", "chrome.exe", 200));
        collector.capture_request(test_request("GET", "https://b.com", "firefox.exe", 200));
        collector.capture_request(test_request("GET", "https://c.com", "chrome.exe", 301));
        let chrome = collector.get_requests_by_process("chrome.exe");
        assert_eq!(chrome.len(), 2);
    }

    #[test]
    fn test_get_requests_by_method_and_status() {
        let mut collector = HttpCollector::new(test_bus());
        collector.capture_request(test_request("GET", "https://a.com", "p.exe", 200));
        collector.capture_request(test_request("POST", "https://b.com", "p.exe", 404));
        collector.capture_request(test_request("GET", "https://c.com", "p.exe", 500));
        assert_eq!(collector.get_requests_by_method("GET").len(), 2);
        assert_eq!(collector.get_requests_by_status(200).len(), 1);
        assert_eq!(collector.get_requests_by_status(404).len(), 1);
    }

    #[test]
    fn test_bytes_tracking() {
        let mut collector = HttpCollector::new(test_bus());
        let mut req1 = test_request("GET", "https://a.com", "p.exe", 200);
        req1.bytes_sent = 100;
        req1.bytes_received = 200;
        let mut req2 = test_request("GET", "https://b.com", "p.exe", 200);
        req2.bytes_sent = 300;
        req2.bytes_received = 400;
        collector.capture_request(req1);
        collector.capture_request(req2);
        assert_eq!(collector.total_bytes_sent(), 400);
        assert_eq!(collector.total_bytes_received(), 600);
    }

    #[test]
    fn test_max_requests_overflow() {
        let mut collector = HttpCollector::with_max_requests(test_bus(), 3);
        for i in 0..5 {
            collector.capture_request(test_request("GET", &format!("https://{}.com", i), "p.exe", 200));
        }
        assert_eq!(collector.request_count(), 3);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = HttpCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_clear() {
        let mut collector = HttpCollector::new(test_bus());
        collector.capture_request(test_request("GET", "https://a.com", "p.exe", 200));
        assert_eq!(collector.request_count(), 1);
        collector.clear();
        assert_eq!(collector.request_count(), 0);
    }

    #[test]
    fn test_get_requests_by_domain() {
        let mut collector = HttpCollector::new(test_bus());
        collector.capture_request(test_request("GET", "https://evil.com/path", "p.exe", 200));
        collector.capture_request(test_request("GET", "https://good.com/path", "p.exe", 200));
        let evil = collector.get_requests_by_domain("evil.com");
        assert_eq!(evil.len(), 1);
    }

    #[test]
    fn test_etw_events_captured_initial() {
        let collector = HttpCollector::new(test_bus());
        assert_eq!(collector.etw_events_captured(), 0);
    }

    #[test]
    fn test_sync_etw_events_empty() {
        let mut collector = HttpCollector::new(test_bus());
        collector.sync_etw_events();
        assert_eq!(collector.request_count(), 0);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_enable_disable_etw_stubs() {
        let mut collector = HttpCollector::new(test_bus());
        assert!(collector.enable_http_etw_tracing().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.disable_http_etw_tracing().is_ok());
        assert!(!collector.is_collecting());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_enable_disable_etw_real() {
        let mut collector = HttpCollector::new(test_bus());
        let result = collector.enable_http_etw_tracing();
        if result.is_ok() {
            assert!(collector.is_collecting());
            assert!(collector.disable_http_etw_tracing().is_ok());
            assert!(!collector.is_collecting());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_build_http_properties_buffer() {
        let name = HttpCollector::logger_name_wide_http();
        let buffer = HttpCollector::build_http_properties_buffer(&name);
        assert!(buffer.len() > std::mem::size_of::<EVENT_TRACE_PROPERTIES>());
        let props = unsafe { &*(buffer.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
        assert_eq!(props.Wnode.BufferSize, buffer.len() as u32);
        assert!(props.LoggerNameOffset as usize >= std::mem::size_of::<EVENT_TRACE_PROPERTIES>());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_logger_name_wide_http() {
        let name = HttpCollector::logger_name_wide_http();
        assert!(!name.is_empty());
        assert_eq!(*name.last().unwrap(), 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_http_etw_event_too_short() {
        assert!(HttpCollector::parse_http_etw_event(&[]).is_none());
        assert!(HttpCollector::parse_http_etw_event(&[0, 0]).is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_http_etw_event_connection() {
        let mut data = vec![1u8, 0, 1, 0];
        data.extend_from_slice(&42u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let event = HttpCollector::parse_http_etw_event(&data);
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.method, "CONNECT");
        assert!(e.url.contains("42"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_http_etw_event_request() {
        let mut data = vec![2u8, 0, 1, 0];
        data.extend_from_slice(&99u64.to_le_bytes());
        data.extend_from_slice(&200u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&1024u64.to_le_bytes());
        let event = HttpCollector::parse_http_etw_event(&data);
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.method, "POST");
        assert_eq!(e.status_code, 200);
        assert_eq!(e.bytes_sent, 1024);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_http_etw_event_response() {
        let mut data = vec![3u8, 0, 1, 0];
        data.extend_from_slice(&404u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 2]);
        data.extend_from_slice(&2048u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        let event = HttpCollector::parse_http_etw_event(&data);
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.method, "RESPONSE");
        assert_eq!(e.status_code, 404);
        assert_eq!(e.bytes_received, 2048);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_http_etw_event_unknown_id() {
        let data = vec![99u8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(HttpCollector::parse_http_etw_event(&data).is_none());
    }
}
