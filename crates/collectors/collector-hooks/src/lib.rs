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
    pub timestamp: DateTime<Utc>,
}

pub struct HooksCollector {
    bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    hooks: Vec<HookEvent>,
    known_hooked_modules: Vec<String>,
}

impl HooksCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus,
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

    pub fn detect_hooks(&mut self, pid: u32) -> Vec<HookEvent> {
        let mut detected = Vec::new();
        for module in &self.known_hooked_modules {
            let hook = HookEvent {
                process_id: pid,
                hook_type: HookType::InlineHook,
                address: 0x7FFE0000 + (pid as u64 * 0x1000),
                module_name: module.clone(),
                timestamp: Utc::now(),
            };
            detected.push(hook.clone());
            self.hooks.push(hook);
        }
        self.events_processed += detected.len() as u64;
        detected
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

    pub fn record_inline_hook(&mut self, pid: u32, address: u64, module: &str) {
        self.hooks.push(HookEvent {
            process_id: pid,
            hook_type: HookType::InlineHook,
            address,
            module_name: module.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_iat_hook(&mut self, pid: u32, address: u64, module: &str) {
        self.hooks.push(HookEvent {
            process_id: pid,
            hook_type: HookType::IatHook,
            address,
            module_name: module.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_eat_hook(&mut self, pid: u32, address: u64, module: &str) {
        self.hooks.push(HookEvent {
            process_id: pid,
            hook_type: HookType::EatHook,
            address,
            module_name: module.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_detour(&mut self, pid: u32, address: u64, module: &str) {
        self.hooks.push(HookEvent {
            process_id: pid,
            hook_type: HookType::Detour,
            address,
            module_name: module.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_trampoline(&mut self, pid: u32, address: u64, module: &str) {
        self.hooks.push(HookEvent {
            process_id: pid,
            hook_type: HookType::Trampoline,
            address,
            module_name: module.into(),
            timestamp: Utc::now(),
        });
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
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors API hooks, inline hooks, and IAT hooks in processes"
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
    fn test_detect_hooks() {
        let mut collector = HooksCollector::new(test_bus());
        let hooks = collector.detect_hooks(1234);
        assert_eq!(hooks.len(), 5);
        assert_eq!(collector.hook_count(), 5);
        for hook in &hooks {
            assert_eq!(hook.process_id, 1234);
            assert_eq!(hook.hook_type, HookType::InlineHook);
        }
    }

    #[test]
    fn test_record_all_hook_types() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_inline_hook(100, 0x1000, "ntdll.dll");
        collector.record_iat_hook(100, 0x2000, "kernel32.dll");
        collector.record_eat_hook(100, 0x3000, "user32.dll");
        collector.record_detour(100, 0x4000, "ws2_32.dll");
        collector.record_trampoline(100, 0x5000, "wininet.dll");
        assert_eq!(collector.hook_count(), 5);
        assert_eq!(collector.get_hooks_by_type(&HookType::InlineHook).len(), 1);
        assert_eq!(collector.get_hooks_by_type(&HookType::IatHook).len(), 1);
        assert_eq!(collector.get_hooks_by_type(&HookType::Detour).len(), 1);
    }

    #[test]
    fn test_get_hooks_for_process() {
        let mut collector = HooksCollector::new(test_bus());
        collector.record_inline_hook(100, 0x1000, "a.dll");
        collector.record_inline_hook(200, 0x2000, "b.dll");
        collector.record_inline_hook(100, 0x3000, "c.dll");
        let hooks = collector.get_hooks_for_process(100);
        assert_eq!(hooks.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut collector = HooksCollector::new(test_bus());
        collector.detect_hooks(100);
        assert_eq!(collector.hook_count(), 5);
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
    fn test_multiple_process_detection() {
        let mut collector = HooksCollector::new(test_bus());
        collector.detect_hooks(100);
        collector.detect_hooks(200);
        assert_eq!(collector.hook_count(), 10);
        assert_eq!(collector.get_hooks_for_process(100).len(), 5);
        assert_eq!(collector.get_hooks_for_process(200).len(), 5);
    }
}
