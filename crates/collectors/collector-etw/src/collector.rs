use async_trait::async_trait;
use royalsecurity_core::module::{SecurityModule, ModuleConfig};
use royalsecurity_common::types::*;
use royalsecurity_core::bus::EventBus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tracing::{info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Etw::*;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::core::PWSTR;

const ETW_REAL_TIME_MODE: u32 = 0x00000100;
const ETW_PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const ETW_PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x01000000;

#[derive(Debug, Clone)]
pub struct EtwProviderConfig {
    pub name: String,
    pub guid: String,
    pub enabled: bool,
    pub level: TraceLevel,
}

#[derive(Debug, Clone)]
pub enum TraceLevel {
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
}

impl TraceLevel {
    pub fn to_value(&self) -> u8 {
        match self {
            Self::Critical => 1,
            Self::Error => 2,
            Self::Warning => 3,
            Self::Information => 4,
            Self::Verbose => 5,
        }
    }
}

#[cfg(target_os = "windows")]
struct EtwContext {
    bus: Arc<EventBus>,
    events_processed: AtomicU64,
    errors: AtomicU64,
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn etw_event_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    if record.UserContext.is_null() || record.UserData.is_null() || record.UserDataLength == 0 {
        return;
    }
    let ctx = &*(record.UserContext as *const EtwContext);
    let user_data = std::slice::from_raw_parts(
        record.UserData as *const u8,
        record.UserDataLength as usize,
    );
    match crate::parser::parse_etw_event(user_data) {
        Ok(Some(envelope)) => {
            ctx.events_processed.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = ctx.bus.publish(envelope.payload) {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                tracing::trace!("ETW callback publish error: {}", e);
            }
        }
        Ok(None) => {}
        Err(e) => {
            ctx.errors.fetch_add(1, Ordering::Relaxed);
            tracing::trace!("ETW callback parse error: {}", e);
        }
    }
}

#[cfg(target_os = "windows")]
struct EtwInner {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    ctx: *mut EtwContext,
}

pub struct EtwCollector {
    bus: Arc<EventBus>,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    providers: Vec<EtwProviderConfig>,
    running: Arc<AtomicBool>,
    #[cfg(target_os = "windows")]
    inner: Option<EtwInner>,
    #[cfg(target_os = "windows")]
    properties_buffer: Vec<u8>,
}

unsafe impl Send for EtwCollector {}
unsafe impl Sync for EtwCollector {}

impl EtwCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus: Arc::new(bus),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            providers: Self::default_providers(),
            running: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "windows")]
            inner: None,
            #[cfg(target_os = "windows")]
            properties_buffer: Vec::new(),
        }
    }

    fn default_providers() -> Vec<EtwProviderConfig> {
        vec![
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-Process".into(),
                guid: "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-FileIO".into(),
                guid: "bed7cf1b-0c93-4be4-b4a7-5b0b0c84e6a8".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-Network".into(),
                guid: "7dd42a49-5329-4832-8dfd-1e22f7e3b6ae".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Kernel-Registry".into(),
                guid: "76577757-7206-4fa2-8069-80ecbc02c22f".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Security-Auditing".into(),
                guid: "54849625-5478-4994-a5ba-3e3b0328c30d".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-PowerShell".into(),
                guid: "a0c1853b-5c40-4b15-8766-3cf1c58f985a".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-WMI-Activity".into(),
                guid: "1418ef04-b0b4-4623-84f0-0f3be4d0de86".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Antimalware-Scan-Interface".into(),
                guid: "2e5e8c86-85dc-47dc-84cf-9a567241aeb5".into(),
                enabled: true,
                level: TraceLevel::Verbose,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-Threat-Intelligence".into(),
                guid: "0ea14858-018a-4401-b4be-f3d0bfb90303".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
            EtwProviderConfig {
                name: "Microsoft-Windows-DNS-Client".into(),
                guid: "1c95122e-7180-4591-9bb3-f44be68d2e25".into(),
                enabled: true,
                level: TraceLevel::Information,
            },
        ]
    }

    pub fn enabled_providers(&self) -> Vec<&EtwProviderConfig> {
        self.providers.iter().filter(|p| p.enabled).collect()
    }

    pub fn add_provider(&mut self, provider: EtwProviderConfig) {
        info!(provider = %provider.name, "Adding ETW provider");
        self.providers.push(provider);
    }

    pub fn remove_provider(&mut self, name: &str) {
        self.providers.retain(|p| p.name != name);
    }

    pub fn process_raw_event(&mut self, raw_data: &[u8]) -> Option<SecurityEventEnvelope> {
        self.events_processed += 1;
        match crate::parser::parse_etw_event(raw_data) {
            Ok(Some(event)) => Some(event),
            Ok(None) => None,
            Err(e) => {
                self.errors += 1;
                tracing::warn!(error = %e, "Failed to parse ETW event");
                None
            }
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

    pub fn stats(&self) -> EtwStats {
        EtwStats {
            events_processed: self.events_processed,
            errors: self.errors,
            providers_active: self.providers.iter().filter(|p| p.enabled).count(),
            eps: self.events_per_second(),
        }
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
        "RoyalsecurityETW"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    #[cfg(target_os = "windows")]
    fn start_session(&mut self) -> Result<(), String> {
        use windows::core::GUID;

        let logger_name = Self::logger_name_wide();
        let mut buffer = Self::build_properties_buffer(&logger_name);
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_pcwstr = unsafe {
            PCWSTR(buffer.as_mut_ptr().add(properties_size) as *const u16)
        };

        unsafe {
            let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
            let result = StartTraceW(&mut session_handle, name_pcwstr, buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            if result.0 != 0 && result.0 != 183 {
                return Err(format!("StartTraceW failed: WIN32_ERROR({})", result.0));
            }
            info!(handle = ?session_handle, "ETW trace session started");

            for provider in self.providers.iter().filter(|p| p.enabled) {
                let guid = GUID::from(provider.guid.as_str());
                let level = provider.level.to_value();
                let result = EnableTraceEx2(
                    session_handle,
                    &guid,
                    1,
                    level,
                    0,
                    0,
                    0,
                    None,
                );
                if result.0 != 0 {
                    warn!(provider = %provider.name, error = result.0, "Failed to enable ETW provider");
                } else {
                    info!(provider = %provider.name, "ETW provider enabled");
                }
            }

            let ctx = Box::into_raw(Box::new(EtwContext {
                bus: Arc::clone(&self.bus),
                events_processed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
            }));

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = PWSTR(buffer.as_mut_ptr().add(properties_size) as *mut u16);
            logfile.Anonymous1 = EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: ETW_PROCESS_TRACE_MODE_REAL_TIME | ETW_PROCESS_TRACE_MODE_EVENT_RECORD,
            };
            logfile.Anonymous2 = EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(etw_event_callback),
            };
            logfile.Context = ctx as *mut _;

            let trace_handle = OpenTraceW(&mut logfile);
            if trace_handle.Value == 0 || trace_handle.Value == u64::MAX {
                let _ = Box::from_raw(ctx);
                return Err(format!("OpenTraceW failed: INVALID_HANDLE (value={})", trace_handle.Value));
            }
            info!(handle = ?trace_handle, "ETW trace opened");

            self.inner = Some(EtwInner {
                session_handle,
                trace_handle,
                ctx,
            });
            self.properties_buffer = buffer;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn stop_session(&mut self) -> Result<(), String> {
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

                let name_pcwstr = PCWSTR(buffer.as_mut_ptr().add(properties_size) as *const u16);

                let result = ControlTraceW(
                    inner.session_handle,
                    name_pcwstr,
                    buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                );
                info!(result = ?result, "ETW trace session stop requested");

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EtwStats {
    pub events_processed: u64,
    pub errors: u64,
    pub providers_active: usize,
    pub eps: f64,
}

#[async_trait]
impl SecurityModule for EtwCollector {
    fn name(&self) -> &str { "ETW Collector" }
    fn version(&self) -> &str { "0.1.0" }
    fn description(&self) -> &str { "Event Tracing for Windows real-time telemetry collector" }

    async fn initialize(&mut self, config: ModuleConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("ETW Collector initialized with {} providers", self.providers.len());
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.start_time = Some(Instant::now());
        self.running.store(true, Ordering::SeqCst);

        #[cfg(target_os = "windows")]
        {
            match self.start_session() {
                Ok(()) => {
                    self.status = ModuleStatus::Running;
                    info!("ETW Collector started with real-time session");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to start ETW real-time session, falling back to no-op");
                    self.status = ModuleStatus::Degraded;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.status = ModuleStatus::Running;
            info!("ETW Collector started (no-op on non-Windows)");
        }

        for provider in self.enabled_providers() {
            info!(provider = %provider.name, guid = %provider.guid, "ETW provider registered");
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.running.store(false, Ordering::SeqCst);
        self.sync_stats_from_context();

        #[cfg(target_os = "windows")]
        if let Err(e) = self.stop_session() {
            warn!(error = %e, "Error stopping ETW session");
        }

        self.status = ModuleStatus::Stopped;
        info!("ETW Collector stopped. Processed {} events", self.events_processed);
        Ok(())
    }

    async fn health(&self) -> ModuleHealth {
        ModuleHealth {
            status: self.status.clone(),
            last_heartbeat: chrono::Utc::now(),
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

    #[test]
    fn test_trace_level_values() {
        assert_eq!(TraceLevel::Critical.to_value(), 1);
        assert_eq!(TraceLevel::Error.to_value(), 2);
        assert_eq!(TraceLevel::Warning.to_value(), 3);
        assert_eq!(TraceLevel::Information.to_value(), 4);
        assert_eq!(TraceLevel::Verbose.to_value(), 5);
    }

    #[test]
    fn test_default_providers() {
        let providers = EtwCollector::default_providers();
        assert_eq!(providers.len(), 10);
        assert!(providers.iter().all(|p| p.enabled));
    }

    #[test]
    fn test_add_remove_provider() {
        let mut collector = EtwCollector::new(test_bus());
        assert_eq!(collector.providers.len(), 10);
        collector.add_provider(EtwProviderConfig {
            name: "CustomProvider".into(),
            guid: "00000000-0000-0000-0000-000000000001".into(),
            enabled: true,
            level: TraceLevel::Verbose,
        });
        assert_eq!(collector.providers.len(), 11);
        collector.remove_provider("CustomProvider");
        assert_eq!(collector.providers.len(), 10);
    }

    #[test]
    fn test_enabled_providers() {
        let mut collector = EtwCollector::new(test_bus());
        let enabled = collector.enabled_providers();
        assert_eq!(enabled.len(), 10);
        collector.providers[0].enabled = false;
        let enabled = collector.enabled_providers();
        assert_eq!(enabled.len(), 9);
    }

    #[test]
    fn test_process_raw_event_empty() {
        let mut collector = EtwCollector::new(test_bus());
        let result = collector.process_raw_event(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_process_raw_event_short() {
        let mut collector = EtwCollector::new(test_bus());
        let result = collector.process_raw_event(&[0, 1]);
        assert!(result.is_none());
    }

    #[test]
    fn test_events_per_second_zero() {
        let collector = EtwCollector::new(test_bus());
        assert_eq!(collector.events_per_second(), 0.0);
    }

    #[test]
    fn test_stats() {
        let collector = EtwCollector::new(test_bus());
        let stats = collector.stats();
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.providers_active, 10);
    }

    #[tokio::test]
    async fn test_initialize_and_health() {
        let mut collector = EtwCollector::new(test_bus());
        collector.initialize(ModuleConfig::default()).await.unwrap();
        let health = collector.health().await;
        assert_eq!(health.status, ModuleStatus::Initialized);
    }

    #[tokio::test]
    async fn test_start_stop() {
        let mut collector = EtwCollector::new(test_bus());
        collector.initialize(ModuleConfig::default()).await.unwrap();
        collector.start().await.unwrap();
        let health = collector.health().await;
        assert!(health.status == ModuleStatus::Running || health.status == ModuleStatus::Degraded);
        collector.stop().await.unwrap();
        assert_eq!(collector.health().await.status, ModuleStatus::Stopped);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_build_properties_buffer() {
        let name = EtwCollector::logger_name_wide();
        let buffer = EtwCollector::build_properties_buffer(&name);
        assert!(buffer.len() > std::mem::size_of::<EVENT_TRACE_PROPERTIES>());
        let props = unsafe { &*(buffer.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
        assert_eq!(props.Wnode.BufferSize, buffer.len() as u32);
        assert!(props.LoggerNameOffset as usize >= std::mem::size_of::<EVENT_TRACE_PROPERTIES>());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_logger_name_wide() {
        let name = EtwCollector::logger_name_wide();
        assert!(!name.is_empty());
        assert_eq!(*name.last().unwrap(), 0);
    }
}
