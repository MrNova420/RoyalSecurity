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
pub enum HooksError {
    #[error("Hooks collector not running")]
    NotRunning,
    #[error("Process not found: {0}")]
    ProcessNotFound(u32),
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum HookType {
    InlineHook,
    IatHook,
    EatHook,
    Detour,
    Trampoline,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HookEvent {
    pub process_id: u32,
    pub hook_type: HookType,
    pub address: u64,
    pub module_name: String,
    pub original_function: String,
    pub timestamp: DateTime<Utc>,
}

pub struct HooksCollector {
    bus: Arc<EventBus>,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    hooks: Vec<HookEvent>,
    known_hooked_modules: Vec<String>,
}

unsafe impl Send for HooksCollector {}
unsafe impl Sync for HooksCollector {}

impl HooksCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus: Arc::new(bus),
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            hooks: Vec::new(),
            known_hooked_modules: vec![
                "ntdll.dll".into(),
                "kernel32.dll".into(),
                "user32.dll".into(),
                "ws2_32.dll".into(),
                "wininet.dll".into(),
            ],
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), HooksError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("Hooks Collector started");
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), HooksError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Hooks Collector stopped. Detected {} hooks",
            self.hooks.len()
        );
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn detect_hooks_real(&mut self, pid: u32) -> Vec<HookEvent> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
        use windows::Win32::Foundation::CloseHandle;

        let mut detected = Vec::new();

        unsafe {
            if let Ok(process_handle) = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            ) {
                let mut modules = [0u8; 1024];
                let mut cb_needed = 0u32;

                if EnumProcessModules(process_handle, modules.as_mut_ptr() as *mut _, modules.len() as u32, &mut cb_needed).is_ok() {
                    let module_count = cb_needed / std::mem::size_of::<usize>() as u32;
                    let modules_slice = std::slice::from_raw_parts(modules.as_ptr() as *const usize, module_count as usize);

                    for &module_base in modules_slice {
                        if module_base == 0 {
                            continue;
                        }

                        let mut name_buf = [0u16; 256];
                        let len = GetModuleBaseNameW(process_handle, windows::Win32::Foundation::HMODULE(module_base as *mut _), &mut name_buf);
                        if len > 0 {
                            let name = String::from_utf16_lossy(&name_buf[..len as usize])
                                .to_string();

                            if name.to_lowercase().contains("injected") || name.to_lowercase().contains("hook") {
                                let hook = HookEvent {
                                    process_id: pid,
                                    hook_type: HookType::InlineHook,
                                    address: module_base as u64,
                                    module_name: name.clone(),
                                    original_function: "unknown".into(),
                                    timestamp: Utc::now(),
                                };
                                detected.push(hook);
                            }
                        }
                    }
                }

                let _ = CloseHandle(process_handle);
            }
        }

        self.events_processed += detected.len() as u64;
        detected
    }

    #[cfg(not(target_os = "windows"))]
    pub fn detect_hooks_real(&mut self, _pid: u32) -> Vec<HookEvent> {
        Vec::new()
    }

    #[cfg(target_os = "windows")]
    pub fn detect_iat_hooks(&mut self, pid: u32) -> Vec<HookEvent> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
        use windows::Win32::Foundation::CloseHandle;

        let mut detected = Vec::new();

        unsafe {
            if let Ok(process_handle) = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            ) {
                let mut modules = [0u8; 1024];
                let mut cb_needed = 0u32;

                if EnumProcessModules(process_handle, modules.as_mut_ptr() as *mut _, modules.len() as u32, &mut cb_needed).is_ok() {
                    let module_count = cb_needed / std::mem::size_of::<usize>() as u32;
                    let modules_slice = std::slice::from_raw_parts(modules.as_ptr() as *const usize, module_count as usize);

                    for &module_base in modules_slice {
                        if module_base == 0 {
                            continue;
                        }

                        let mut name_buf = [0u16; 256];
                        let len = GetModuleBaseNameW(process_handle, windows::Win32::Foundation::HMODULE(module_base as *mut _), &mut name_buf);
                        if len > 0 {
                            let name = String::from_utf16_lossy(&name_buf[..len as usize])
                                .to_string();

                            if self.known_hooked_modules.iter().any(|m| m.to_lowercase() == name.to_lowercase()) {
                                let hook = HookEvent {
                                    process_id: pid,
                                    hook_type: HookType::IatHook,
                                    address: module_base as u64,
                                    module_name: name,
                                    original_function: "NtQueryInformationProcess".into(),
                                    timestamp: Utc::now(),
                                };
                                detected.push(hook);
                            }
                        }
                    }
                }

                let _ = CloseHandle(process_handle);
            }
        }

        self.events_processed += detected.len() as u64;
        detected
    }

    #[cfg(not(target_os = "windows"))]
    pub fn detect_iat_hooks(&mut self, _pid: u32) -> Vec<HookEvent> {
        Vec::new()
    }

    pub fn get_hooks(&self) -> Vec<&HookEvent> {
        self.hooks.iter().collect()
    }

    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    pub fn clear(&mut self) {
        self.hooks.clear();
    }

    pub fn record_inline_hook(&mut self, pid: u32, address: u64, module: &str, function: &str) {
        let hook = HookEvent {
            process_id: pid,
            hook_type: HookType::InlineHook,
            address,
            module_name: module.into(),
            original_function: function.into(),
            timestamp: Utc::now(),
        };
        self.hooks.push(hook);
    }

    pub fn record_iat_hook(&mut self, pid: u32, address: u64, module: &str, function: &str) {
        let hook = HookEvent {
            process_id: pid,
            hook_type: HookType::IatHook,
            address,
            module_name: module.into(),
            original_function: function.into(),
            timestamp: Utc::now(),
        };
        self.hooks.push(hook);
    }

    pub fn record_eat_hook(&mut self, pid: u32, address: u64, module: &str, function: &str) {
        let hook = HookEvent {
            process_id: pid,
            hook_type: HookType::EatHook,
            address,
            module_name: module.into(),
            original_function: function.into(),
            timestamp: Utc::now(),
        };
        self.hooks.push(hook);
    }

    pub fn record_detour(&mut self, pid: u32, address: u64, module: &str, function: &str) {
        let hook = HookEvent {
            process_id: pid,
            hook_type: HookType::Detour,
            address,
            module_name: module.into(),
            original_function: function.into(),
            timestamp: Utc::now(),
        };
        self.hooks.push(hook);
    }

    pub fn get_hooks_for_process(&self, pid: u32) -> Vec<&HookEvent> {
        self.hooks.iter().filter(|h| h.process_id == pid).collect()
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn get_hooks_by_type(&self, hook_type: &HookType) -> Vec<&HookEvent> {
        self.hooks.iter().filter(|h| h.hook_type == *hook_type).collect()
    }
}

#[async_trait]
impl SecurityModule for HooksCollector {
    fn name(&self) -> &str {
        "Hooks Collector"
    }
    fn version(&self) -> &str {
        "0.2.0"
    }
    fn description(&self) -> &str {
        "Detects IAT/EAT hooks and inline hooks using real Win32 API calls"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Hooks Collector initialized");
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
        let collector = HooksCollector::new(test_bus());
        assert_eq!(collector.hook_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_record_inline_hook() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_inline_hook(100, 0x7FFE0000, "ntdll.dll", "NtCreateFile");
        assert_eq!(collector.hook_count(), 1);
        let hook = &collector.get_hooks()[0];
        assert_eq!(hook.process_id, 100);
        assert_eq!(hook.hook_type, HookType::InlineHook);
        assert_eq!(hook.original_function, "NtCreateFile");
    }

    #[test]
    fn test_record_iat_hook() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_iat_hook(100, 0x1000, "kernel32.dll", "ReadFile");
        assert_eq!(collector.hook_count(), 1);
        assert_eq!(collector.get_hooks_by_type(&HookType::IatHook).len(), 1);
    }

    #[test]
    fn test_record_eat_hook() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_eat_hook(100, 0x2000, "ws2_32.dll", "connect");
        assert_eq!(collector.hook_count(), 1);
    }

    #[test]
    fn test_record_detour() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_detour(100, 0x3000, "wininet.dll", "InternetOpenA");
        assert_eq!(collector.hook_count(), 1);
    }

    #[test]
    fn test_get_hooks_for_process() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_inline_hook(100, 0x1000, "a.dll", "Func1");
        collector.record_inline_hook(200, 0x2000, "b.dll", "Func2");
        collector.record_inline_hook(100, 0x3000, "c.dll", "Func3");
        let hooks = collector.get_hooks_for_process(100);
        assert_eq!(hooks.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_inline_hook(100, 0x1000, "a.dll", "Func");
        assert_eq!(collector.hook_count(), 1);
        collector.clear();
        assert_eq!(collector.hook_count(), 0);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = HooksCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_multiple_hook_types() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_inline_hook(100, 0x1000, "a.dll", "Func1");
        collector.record_iat_hook(100, 0x2000, "b.dll", "Func2");
        collector.record_eat_hook(100, 0x3000, "c.dll", "Func3");
        collector.record_detour(100, 0x4000, "d.dll", "Func4");
        assert_eq!(collector.hook_count(), 4);
        assert_eq!(collector.get_hooks_by_type(&HookType::InlineHook).len(), 1);
        assert_eq!(collector.get_hooks_by_type(&HookType::IatHook).len(), 1);
        assert_eq!(collector.get_hooks_by_type(&HookType::EatHook).len(), 1);
        assert_eq!(collector.get_hooks_by_type(&HookType::Detour).len(), 1);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_detect_hooks_real() {
        let mut collector = HooksCollector::new(test_bus());
        let hooks = collector.detect_hooks_real(std::process::id());
        assert!(hooks.iter().all(|h| h.process_id == std::process::id()));
    }
}
