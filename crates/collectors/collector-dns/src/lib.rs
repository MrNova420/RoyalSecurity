pub mod prelude;
pub use royalsecurity_core as core;

use royalsecurity_common::types::*;
use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_core::bus::EventBus;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tracing::{info, warn};
use chrono::{DateTime, Utc};

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Etw::*;
#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, PWSTR};

const ETW_REAL_TIME_MODE: u32 = 0x00000100;
const ETW_PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const ETW_PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x01000000;

const DNS_CLIENT_PROVIDER_GUID: &str = "1c95122e-7180-4591-9bb3-f44be68d2e25";
const DNS_TUNNELING_THRESHOLD: usize = 50;
const DNS_ENTROPY_THRESHOLD: f64 = 3.5;
const MALICIOUS_TLDS: &[&str] = &[
    ".top", ".xyz", ".club", ".work", ".buzz", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".cc", ".ws", ".click", ".download", ".link",
    ".racing", ".win", ".bid", ".stream", ".date", ".review", ".party",
    ".trade", ".accountant", ".science", ".faith", ".loan", ".cricket",
];

pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn is_dga_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let sld = labels[labels.len() - 2];
    if sld.len() < 8 {
        return false;
    }
    let entropy = calculate_entropy(sld);
    entropy >= DNS_ENTROPY_THRESHOLD
}

pub fn is_dns_tunneling(domain: &str) -> bool {
    if let Some((subdomain, _)) = domain.split_once('.') {
        subdomain.len() > DNS_TUNNELING_THRESHOLD
    } else {
        false
    }
}

pub fn is_malicious_tld(domain: &str) -> Option<String> {
    let lower = domain.to_lowercase();
    for &tld in MALICIOUS_TLDS {
        if lower.ends_with(tld) {
            return Some(tld.to_string());
        }
    }
    None
}

pub fn analyze_domain(domain: &str, pid: u32) -> Vec<SuspiciousDnsActivity> {
    let mut activities = Vec::new();
    if let Some(tld) = is_malicious_tld(domain) {
        activities.push(SuspiciousDnsActivity::MaliciousTld {
            domain: domain.to_string(),
            tld,
            process_id: pid,
        });
    }
    if is_dga_domain(domain) {
        let entropy = calculate_entropy(domain);
        activities.push(SuspiciousDnsActivity::DgaDomain {
            domain: domain.to_string(),
            entropy,
            process_id: pid,
        });
    }
    if is_dns_tunneling(domain) {
        let subdomain_len = domain.split('.').next().map(|s| s.len()).unwrap_or(0);
        activities.push(SuspiciousDnsActivity::DnsTunneling {
            domain: domain.to_string(),
            subdomain_length: subdomain_len,
            process_id: pid,
        });
    }
    activities
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DnsQueryType {
    A,
    AAAA,
    MX,
    TXT,
    CNAME,
    NS,
    SOA,
    PTR,
    SRV,
    SVCB,
    HTTPS,
    Unknown(u16),
}

impl DnsQueryType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::AAAA,
            15 => Self::MX,
            16 => Self::TXT,
            5 => Self::CNAME,
            2 => Self::NS,
            6 => Self::SOA,
            12 => Self::PTR,
            33 => Self::SRV,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            other => Self::Unknown(other),
        }
    }

    pub fn to_string_label(&self) -> &str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::CNAME => "CNAME",
            Self::NS => "NS",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::SRV => "SRV",
            Self::SVCB => "SVCB",
            Self::HTTPS => "HTTPS",
            Self::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SuspiciousDnsActivity {
    DgaDomain {
        domain: String,
        entropy: f64,
        process_id: u32,
    },
    DnsTunneling {
        domain: String,
        subdomain_length: usize,
        process_id: u32,
    },
    MaliciousTld {
        domain: String,
        tld: String,
        process_id: u32,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsEventInfo {
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub response_ips: Vec<String>,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub is_response: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsStats {
    pub events_processed: u64,
    pub errors: u64,
    pub captures: usize,
    pub suspicious_activities: usize,
    pub eps: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsCollectorError {
    #[error("DNS collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapturedDns {
    pub query: String,
    pub response: Option<String>,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsCaptureConfig {
    pub capture_queries: bool,
    pub capture_responses: bool,
    pub filter_domains: Vec<String>,
}

impl Default for DnsCaptureConfig {
    fn default() -> Self {
        Self {
            capture_queries: true,
            capture_responses: true,
            filter_domains: Vec::new(),
        }
    }
}

#[cfg(target_os = "windows")]
struct DnsEtwContext {
    bus: Arc<EventBus>,
    captures: Arc<Mutex<Vec<CapturedDns>>>,
    suspicious: Arc<Mutex<Vec<SuspiciousDnsActivity>>>,
    events_processed: AtomicU64,
    errors: AtomicU64,
}

#[cfg(target_os = "windows")]
unsafe impl Send for DnsEtwContext {}
#[cfg(target_os = "windows")]
unsafe impl Sync for DnsEtwContext {}

#[cfg(target_os = "windows")]
struct DnsEtwInner {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    ctx: *mut DnsEtwContext,
    process_trace_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn dns_etw_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    if record.UserContext.is_null() {
        return;
    }
    let ctx = &*(record.UserContext as *const DnsEtwContext);
    let pid = record.EventHeader.ProcessId;

    let user_data = if !record.UserData.is_null() && record.UserDataLength > 0 {
        std::slice::from_raw_parts(
            record.UserData as *const u8,
            record.UserDataLength as usize,
        )
    } else {
        ctx.events_processed.fetch_add(1, Ordering::Relaxed);
        return;
    };

    match parse_dns_event_data(user_data, pid) {
        Some(info) => {
            ctx.events_processed.fetch_add(1, Ordering::Relaxed);

            let captured = CapturedDns {
                query: info.query_name.clone(),
                response: if info.is_response {
                    info.response_ips.first().cloned()
                } else {
                    None
                },
                process_name: format!("pid:{}", info.pid),
                pid: info.pid,
                timestamp: info.timestamp,
            };

            ctx.captures.lock().unwrap().push(captured);

            let suspicious = analyze_domain(&info.query_name, info.pid);
            if !suspicious.is_empty() {
                ctx.suspicious.lock().unwrap().extend(suspicious);
            }

            let dns_event = DnsEvent {
                query: info.query_name,
                query_type: info.query_type.to_string_label().to_string(),
                response: info.response_ips.first().cloned(),
                response_code: None,
                timestamp: Utc::now(),
            };
            if let Err(e) = ctx.bus.publish(SecurityEvent::Dns(dns_event)) {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                tracing::trace!("DNS ETW callback publish error: {}", e);
            }
        }
        None => {
            ctx.events_processed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn decode_utf16_trimmed(data: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in data.chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(code as u32) {
            chars.push(ch);
        }
    }
    chars.into_iter().collect()
}

fn parse_dns_event_data(data: &[u8], pid: u32) -> Option<DnsEventInfo> {
    if data.len() < 12 {
        return None;
    }
    let _status = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let _flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let name_length = u16::from_le_bytes([data[8], data[9]]) as usize;

    if name_length == 0 || 10 + name_length > data.len() {
        return None;
    }

    let name_bytes = &data[10..10 + name_length];
    let query_name = decode_utf16_trimmed(name_bytes);

    if query_name.is_empty() || !query_name.contains('.') {
        return None;
    }

    let type_offset = 10 + name_length;
    let query_type = if type_offset + 2 <= data.len() {
        u16::from_le_bytes([data[type_offset], data[type_offset + 1]])
    } else {
        1
    };

    let mut response_ips = Vec::new();
    let ip_start = type_offset + 2;
    if ip_start + 4 <= data.len() {
        let mut offset = ip_start;
        while offset + 4 <= data.len() {
            let octets = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 {
                break;
            }
            response_ips.push(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]));
            offset += 4;
        }
    }

    let is_response = !response_ips.is_empty();

    Some(DnsEventInfo {
        query_name,
        query_type: DnsQueryType::from_u16(query_type),
        response_ips,
        pid,
        timestamp: Utc::now(),
        is_response,
    })
}

pub struct DnsCollector {
    bus: Arc<EventBus>,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    captures: Arc<Mutex<Vec<CapturedDns>>>,
    capture_config: DnsCaptureConfig,
    running: Arc<AtomicBool>,
    suspicious_activities: Arc<Mutex<Vec<SuspiciousDnsActivity>>>,
    #[cfg(target_os = "windows")]
    inner: Option<DnsEtwInner>,
    #[cfg(target_os = "windows")]
    properties_buffer: Vec<u8>,
}

unsafe impl Send for DnsCollector {}
unsafe impl Sync for DnsCollector {}

impl DnsCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus: Arc::new(bus),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            captures: Arc::new(Mutex::new(Vec::new())),
            capture_config: DnsCaptureConfig::default(),
            running: Arc::new(AtomicBool::new(false)),
            suspicious_activities: Arc::new(Mutex::new(Vec::new())),
            #[cfg(target_os = "windows")]
            inner: None,
            #[cfg(target_os = "windows")]
            properties_buffer: Vec::new(),
        }
    }

    pub fn with_config(bus: EventBus, capture_config: DnsCaptureConfig) -> Self {
        Self {
            bus: Arc::new(bus),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            captures: Arc::new(Mutex::new(Vec::new())),
            capture_config,
            running: Arc::new(AtomicBool::new(false)),
            suspicious_activities: Arc::new(Mutex::new(Vec::new())),
            #[cfg(target_os = "windows")]
            inner: None,
            #[cfg(target_os = "windows")]
            properties_buffer: Vec::new(),
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), DnsCollectorError> {
        self.start_time = Some(Instant::now());
        self.running.store(true, Ordering::SeqCst);

        #[cfg(target_os = "windows")]
        {
            match self.start_etw_session() {
                Ok(()) => {
                    self.status = ModuleStatus::Running;
                    info!("DNS Collector started with ETW real-time session");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start ETW session for DNS, falling back to manual mode");
                    self.status = ModuleStatus::Degraded;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.status = ModuleStatus::Running;
            info!("DNS Collector started (no ETW on non-Windows)");
        }

        info!(
            "DNS Collector started with {} captures",
            self.captures.lock().unwrap().len()
        );
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), DnsCollectorError> {
        self.running.store(false, Ordering::SeqCst);
        self.sync_stats_from_context();

        #[cfg(target_os = "windows")]
        if let Err(e) = self.stop_etw_session() {
            warn!(error = %e, "Error stopping ETW session");
        }

        self.status = ModuleStatus::Stopped;
        let count = self.captures.lock().unwrap().len();
        info!("DNS Collector stopped. Captured {} queries", count);
        Ok(())
    }

    pub fn capture_query(&mut self, dns: CapturedDns) {
        if self.capture_config.capture_queries {
            if self.capture_config.filter_domains.is_empty()
                || self
                    .capture_config
                    .filter_domains
                    .iter()
                    .any(|f| dns.query.contains(f.as_str()))
            {
                self.captures.lock().unwrap().push(dns);
            }
        }
    }

    pub fn get_captures(&self) -> Vec<CapturedDns> {
        self.captures.lock().unwrap().clone()
    }

    pub fn capture_count(&self) -> usize {
        self.captures.lock().unwrap().len()
    }

    pub fn clear(&mut self) {
        self.captures.lock().unwrap().clear();
    }

    pub fn get_captures_for_process(&self, process_name: &str) -> Vec<CapturedDns> {
        self.captures
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.process_name == process_name)
            .cloned()
            .collect()
    }

    pub fn get_captures_by_domain(&self, domain: &str) -> Vec<CapturedDns> {
        self.captures
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.query.contains(domain))
            .cloned()
            .collect()
    }

    pub fn set_filter_domains(&mut self, domains: Vec<String>) {
        self.capture_config.filter_domains = domains;
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running || self.status == ModuleStatus::Degraded
    }

    pub fn update_config(&mut self, config: DnsCaptureConfig) {
        self.capture_config = config;
    }

    pub fn suspicious_activities(&self) -> Vec<SuspiciousDnsActivity> {
        self.suspicious_activities.lock().unwrap().clone()
    }

    pub fn stats(&self) -> DnsStats {
        let captures = self.captures.lock().unwrap();
        let suspicious = self.suspicious_activities.lock().unwrap();
        DnsStats {
            events_processed: self.events_processed,
            errors: self.errors,
            captures: captures.len(),
            suspicious_activities: suspicious.len(),
            eps: self.events_per_second(),
        }
    }

    pub fn events_per_second(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.events_processed as f64 / elapsed;
            }
        }
        0.0
    }

    #[cfg(target_os = "windows")]
    fn build_properties_buffer(logger_name: &[u16]) -> Vec<u8> {
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = logger_name.len() * 2;
        let buffer_size = properties_size + name_bytes + 64;
        let mut buffer = vec![0u8; buffer_size];

        unsafe {
            let props = &mut *(buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            props.Wnode.BufferSize = buffer_size as u32;
            props.Wnode.Flags = 0x00000001;
            props.BufferSize = 64;
            props.MinimumBuffers = 16;
            props.MaximumBuffers = 256;
            props.LogFileMode = ETW_REAL_TIME_MODE;
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
    fn logger_name_wide() -> Vec<u16> {
        "RoyalsecurityDNS"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    #[cfg(target_os = "windows")]
    fn start_etw_session(&mut self) -> Result<(), String> {
        use windows::core::GUID;

        let logger_name = Self::logger_name_wide();
        let mut buffer = Self::build_properties_buffer(&logger_name);
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_pcwstr = unsafe {
            PCWSTR(buffer.as_mut_ptr().add(properties_size) as *const u16)
        };

        unsafe {
            let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
            let result = StartTraceW(
                &mut session_handle,
                name_pcwstr,
                buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            );
            if result.0 != 0 && result.0 != 183 {
                return Err(format!("StartTraceW failed: WIN32_ERROR({})", result.0));
            }
            info!(handle = ?session_handle, "DNS ETW trace session started");

            let guid = GUID::from(DNS_CLIENT_PROVIDER_GUID);
            let result = EnableTraceEx2(
                session_handle,
                &guid,
                1,
                4,
                0,
                0,
                0,
                None,
            );
            if result.0 != 0 {
                warn!(
                    provider = "Microsoft-Windows-DNS-Client",
                    error = result.0,
                    "Failed to enable DNS Client ETW provider"
                );
            } else {
                info!(provider = "Microsoft-Windows-DNS-Client", "DNS Client ETW provider enabled");
            }

            let captures = Arc::clone(&self.captures);
            let suspicious = Arc::clone(&self.suspicious_activities);
            let ctx = Box::into_raw(Box::new(DnsEtwContext {
                bus: Arc::clone(&self.bus),
                captures,
                suspicious,
                events_processed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
            }));

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = PWSTR(buffer.as_mut_ptr().add(properties_size) as *mut u16);
            logfile.Anonymous1 = EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: ETW_PROCESS_TRACE_MODE_REAL_TIME
                    | ETW_PROCESS_TRACE_MODE_EVENT_RECORD,
            };
            logfile.Anonymous2 = EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(dns_etw_callback),
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
            info!(handle = ?trace_handle, "DNS ETW trace opened");

            let th = trace_handle;
            let process_trace_thread = std::thread::Builder::new()
                .name("dns-etw-process-trace".into())
                .spawn(move || {
                    let handles = [th];
                    let _ = ProcessTrace(&handles, None, None);
                })
                .map_err(|e| format!("Failed to spawn ProcessTrace thread: {}", e))?;

            self.inner = Some(DnsEtwInner {
                session_handle,
                trace_handle,
                ctx,
                process_trace_thread: Some(process_trace_thread),
            });
            self.properties_buffer = buffer;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn stop_etw_session(&mut self) -> Result<(), String> {
        if let Some(inner) = self.inner.take() {
            unsafe {
                let logger_name = Self::logger_name_wide();
                let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
                let name_bytes = logger_name.len() * 2;
                let buffer_size = properties_size + name_bytes + 64;
                let mut buffer = vec![0u8; buffer_size];
                {
                    let props = &mut *(buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                    props.Wnode.BufferSize = buffer_size as u32;
                    props.LoggerNameOffset = properties_size as u32;
                }
                std::ptr::copy_nonoverlapping(
                    logger_name.as_ptr(),
                    buffer.as_mut_ptr().add(properties_size) as *mut u16,
                    logger_name.len(),
                );

                let name_pcwstr =
                    PCWSTR(buffer.as_mut_ptr().add(properties_size) as *const u16);

                let result = ControlTraceW(
                    inner.session_handle,
                    name_pcwstr,
                    buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                );
                info!(result = ?result, "DNS ETW trace session stop requested");

                if let Some(thread) = inner.process_trace_thread {
                    let _ = thread.join();
                }

                if inner.trace_handle.Value != 0 && inner.trace_handle.Value != u64::MAX {
                    let _ = CloseTrace(inner.trace_handle);
                }

                let _ = Box::from_raw(inner.ctx);
            }
            self.properties_buffer.clear();
        }
        Ok(())
    }

    fn sync_stats_from_context(&mut self) {
        #[cfg(target_os = "windows")]
        if let Some(ref inner) = self.inner {
            unsafe {
                let ctx = &*inner.ctx;
                self.events_processed = ctx.events_processed.load(Ordering::Relaxed);
                self.errors = ctx.errors.load(Ordering::Relaxed);
            }
        }
    }
}

#[async_trait]
impl SecurityModule for DnsCollector {
    fn name(&self) -> &str {
        "DNS Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Captures DNS queries and responses via ETW for analysis"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("DNS Collector initialized");
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
            events_per_second: self.events_per_second(),
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

    fn test_dns(query: &str, process: &str) -> CapturedDns {
        CapturedDns {
            query: query.into(),
            response: Some("1.2.3.4".into()),
            process_name: process.into(),
            pid: 100,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_new_collector() {
        let collector = DnsCollector::new(test_bus());
        assert_eq!(collector.capture_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_capture_and_retrieve() {
        let mut collector = DnsCollector::new(test_bus());
        collector.capture_query(test_dns("evil.com", "chrome.exe"));
        collector.capture_query(test_dns("google.com", "chrome.exe"));
        assert_eq!(collector.capture_count(), 2);
        let captures = collector.get_captures();
        assert_eq!(captures.len(), 2);
    }

    #[test]
    fn test_filter_domains() {
        let config = DnsCaptureConfig {
            capture_queries: true,
            capture_responses: true,
            filter_domains: vec!["evil.com".into()],
        };
        let mut collector = DnsCollector::with_config(test_bus(), config);
        collector.capture_query(test_dns("evil.com", "chrome.exe"));
        collector.capture_query(test_dns("google.com", "chrome.exe"));
        assert_eq!(collector.capture_count(), 1);
        assert_eq!(collector.get_captures()[0].query, "evil.com");
    }

    #[test]
    fn test_get_captures_for_process() {
        let mut collector = DnsCollector::new(test_bus());
        collector.capture_query(test_dns("a.com", "chrome.exe"));
        collector.capture_query(test_dns("b.com", "firefox.exe"));
        let chrome = collector.get_captures_for_process("chrome.exe");
        assert_eq!(chrome.len(), 1);
        assert_eq!(chrome[0].query, "a.com");
    }

    #[test]
    fn test_clear() {
        let mut collector = DnsCollector::new(test_bus());
        collector.capture_query(test_dns("a.com", "proc.exe"));
        assert_eq!(collector.capture_count(), 1);
        collector.clear();
        assert_eq!(collector.capture_count(), 0);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = DnsCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_captures_by_domain() {
        let mut collector = DnsCollector::new(test_bus());
        collector.capture_query(test_dns("evil.com", "p1.exe"));
        collector.capture_query(test_dns("evil.com", "p2.exe"));
        collector.capture_query(test_dns("good.com", "p1.exe"));
        let evil = collector.get_captures_by_domain("evil.com");
        assert_eq!(evil.len(), 2);
    }

    #[test]
    fn test_dns_query_type_from_u16() {
        assert_eq!(DnsQueryType::from_u16(1), DnsQueryType::A);
        assert_eq!(DnsQueryType::from_u16(28), DnsQueryType::AAAA);
        assert_eq!(DnsQueryType::from_u16(15), DnsQueryType::MX);
        assert_eq!(DnsQueryType::from_u16(16), DnsQueryType::TXT);
        assert_eq!(DnsQueryType::from_u16(5), DnsQueryType::CNAME);
        assert_eq!(DnsQueryType::from_u16(2), DnsQueryType::NS);
        assert_eq!(DnsQueryType::from_u16(6), DnsQueryType::SOA);
        assert_eq!(DnsQueryType::from_u16(12), DnsQueryType::PTR);
        assert_eq!(DnsQueryType::from_u16(33), DnsQueryType::SRV);
        assert_eq!(DnsQueryType::from_u16(64), DnsQueryType::SVCB);
        assert_eq!(DnsQueryType::from_u16(65), DnsQueryType::HTTPS);
        assert_eq!(DnsQueryType::from_u16(99), DnsQueryType::Unknown(99));
    }

    #[test]
    fn test_dns_query_type_label() {
        assert_eq!(DnsQueryType::A.to_string_label(), "A");
        assert_eq!(DnsQueryType::AAAA.to_string_label(), "AAAA");
        assert_eq!(DnsQueryType::MX.to_string_label(), "MX");
        assert_eq!(DnsQueryType::TXT.to_string_label(), "TXT");
        assert_eq!(DnsQueryType::CNAME.to_string_label(), "CNAME");
        assert_eq!(DnsQueryType::Unknown(99).to_string_label(), "Unknown");
    }

    #[test]
    fn test_calculate_entropy() {
        assert_eq!(calculate_entropy(""), 0.0);
        assert!(calculate_entropy("aaaaaaa") < 1.0);
        assert!(calculate_entropy("abcdefghij") > 2.0);
        let high = calculate_entropy("xkqjzwvfmn");
        assert!(high > 3.0);
    }

    #[test]
    fn test_dga_detection_normal_domain() {
        assert!(!is_dga_domain("google.com"));
        assert!(!is_dga_domain("example.com"));
        assert!(!is_dga_domain("microsoft.com"));
        assert!(!is_dga_domain("ab.com"));
    }

    #[test]
    fn test_dga_detection_random_domain() {
        let dga = "xkqjzwvfmnrot.com";
        assert!(is_dga_domain(dga));
        let dga2 = "qwrfkmxpobvzla.net";
        assert!(is_dga_domain(dga2));
    }

    #[test]
    fn test_dga_detection_short_label_not_dga() {
        assert!(!is_dga_domain("short.com"));
        assert!(!is_dga_domain("abc123.com"));
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let long_subdomain = "a".repeat(60);
        let tunnel_domain = format!("{}.example.com", long_subdomain);
        assert!(is_dns_tunneling(&tunnel_domain));

        assert!(!is_dns_tunneling("google.com"));
        assert!(!is_dns_tunneling("sub.example.com"));
        assert!(!is_dns_tunneling("a.com"));
    }

    #[test]
    fn test_malicious_tld_detection() {
        assert_eq!(is_malicious_tld("malware.top"), Some(".top".into()));
        assert_eq!(is_malicious_tld("phishing.xyz"), Some(".xyz".into()));
        assert_eq!(is_malicious_tld("spam.tk"), Some(".tk".into()));
        assert_eq!(is_malicious_tld("scam.ml"), Some(".ml".into()));
        assert_eq!(is_malicious_tld("bad.club"), Some(".club".into()));
        assert_eq!(is_malicious_tld("google.com"), None);
        assert_eq!(is_malicious_tld("microsoft.com"), None);
    }

    #[test]
    fn test_analyze_domain_clean() {
        let result = analyze_domain("google.com", 1234);
        assert!(result.is_empty());
    }

    #[test]
    fn test_analyze_domain_malicious_tld() {
        let result = analyze_domain("evil.top", 1234);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], SuspiciousDnsActivity::MaliciousTld { .. }));
    }

    #[test]
    fn test_analyze_domain_dga() {
        let result = analyze_domain("xkqjzwvfmnrot.com", 1234);
        assert!(result.iter().any(|a| matches!(a, SuspiciousDnsActivity::DgaDomain { .. })));
    }

    #[test]
    fn test_analyze_domain_tunneling() {
        let long_sub = "a".repeat(60);
        let domain = format!("{}.example.com", long_sub);
        let result = analyze_domain(&domain, 1234);
        assert!(result.iter().any(|a| matches!(a, SuspiciousDnsActivity::DnsTunneling { .. })));
    }

    #[test]
    fn test_analyze_domain_multiple_threats() {
        let long_sub = "a".repeat(60);
        let domain = format!("{}.top", long_sub);
        let result = analyze_domain(&domain, 1234);
        assert!(result.len() >= 2);
    }

    #[test]
    fn test_parse_dns_event_data_too_short() {
        assert!(parse_dns_event_data(&[0u8; 4], 100).is_none());
    }

    #[test]
    fn test_parse_dns_event_data_valid() {
        let name = "example.com";
        let name_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain(std::iter::once(0u16).flat_map(|c| c.to_le_bytes()))
            .collect();
        let name_len = name_utf16.len() as u16;

        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&name_len.to_le_bytes());
        data.extend_from_slice(&name_utf16);
        data.extend_from_slice(&1u16.to_le_bytes());

        let result = parse_dns_event_data(&data, 42);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.query_name, "example.com");
        assert_eq!(info.query_type, DnsQueryType::A);
        assert_eq!(info.pid, 42);
        assert!(!info.is_response);
        assert!(info.response_ips.is_empty());
    }

    #[test]
    fn test_parse_dns_event_data_no_domain() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);

        assert!(parse_dns_event_data(&data, 1).is_none());
    }

    #[test]
    fn test_parse_dns_event_data_with_response_ips() {
        let name = "test.com";
        let name_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain(std::iter::once(0u16).flat_map(|c| c.to_le_bytes()))
            .collect();
        let name_len = name_utf16.len() as u16;

        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&name_len.to_le_bytes());
        data.extend_from_slice(&name_utf16);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&[93u8, 184, 216, 34]);

        let result = parse_dns_event_data(&data, 99);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.is_response);
        assert_eq!(info.response_ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn test_stats() {
        let collector = DnsCollector::new(test_bus());
        let stats = collector.stats();
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.captures, 0);
        assert_eq!(stats.suspicious_activities, 0);
    }

    #[test]
    fn test_events_per_second_zero() {
        let collector = DnsCollector::new(test_bus());
        assert_eq!(collector.events_per_second(), 0.0);
    }

    #[test]
    fn test_suspicious_activities_empty() {
        let collector = DnsCollector::new(test_bus());
        assert!(collector.suspicious_activities().is_empty());
    }

    #[test]
    fn test_decode_utf16_trimmed() {
        let input = [72u8, 0, 105, 0, 0, 0];
        assert_eq!(decode_utf16_trimmed(&input), "Hi");
    }

    #[test]
    fn test_set_filter_domains() {
        let mut collector = DnsCollector::new(test_bus());
        collector.set_filter_domains(vec!["bad.com".into()]);
        collector.capture_query(test_dns("bad.com", "proc"));
        collector.capture_query(test_dns("good.com", "proc"));
        assert_eq!(collector.capture_count(), 1);
    }

    #[tokio::test]
    async fn test_initialize_and_health() {
        let mut collector = DnsCollector::new(test_bus());
        collector.initialize(ModuleConfig::default()).await.unwrap();
        let health = collector.health().await;
        assert_eq!(health.status, ModuleStatus::Initialized);
    }

    #[tokio::test]
    async fn test_module_start_stop() {
        let mut collector = DnsCollector::new(test_bus());
        collector.initialize(ModuleConfig::default()).await.unwrap();
        collector.start().unwrap();
        let health = collector.health().await;
        assert!(
            health.status == ModuleStatus::Running || health.status == ModuleStatus::Degraded
        );
        collector.stop().unwrap();
        assert_eq!(collector.health().await.status, ModuleStatus::Stopped);
    }
}
