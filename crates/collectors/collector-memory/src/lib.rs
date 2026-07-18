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
pub enum MemoryCollectorError {
    #[error("Memory collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryAllocEvent {
    pub process_id: u32,
    pub base_address: u64,
    pub size: u64,
    pub protection: String,
    pub allocation_type: String,
    pub timestamp: DateTime<Utc>,
}

pub struct MemoryCollector {
    bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    allocations: Vec<MemoryAllocEvent>,
    max_allocations: usize,
}

impl MemoryCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            allocations: Vec::new(),
            max_allocations: 100_000,
        }
    }

    pub fn with_max_allocations(bus: EventBus, max: usize) -> Self {
        Self {
            max_allocations: max,
            ..Self::new(bus)
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), MemoryCollectorError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!(
            "Memory Collector started with {} allocations",
            self.allocations.len()
        );
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), MemoryCollectorError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Memory Collector stopped. Captured {} allocations",
            self.allocations.len()
        );
        Ok(())
    }

    pub fn capture_allocation(&mut self, event: MemoryAllocEvent) {
        if self.allocations.len() >= self.max_allocations {
            self.allocations.remove(0);
        }
        self.allocations.push(event);
    }

    pub fn get_allocations(&self) -> Vec<&MemoryAllocEvent> {
        self.allocations.iter().collect()
    }

    pub fn get_allocations_for_process(&self, pid: u32) -> Vec<&MemoryAllocEvent> {
        self.allocations
            .iter()
            .filter(|a| a.process_id == pid)
            .collect()
    }

    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    pub fn clear(&mut self) {
        self.allocations.clear();
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn get_executable_allocations(&self) -> Vec<&MemoryAllocEvent> {
        self.allocations
            .iter()
            .filter(|a| {
                a.protection.to_uppercase().contains("EXECUTE")
                    || a.allocation_type.to_uppercase().contains("CODE")
            })
            .collect()
    }

    pub fn total_allocated_bytes(&self) -> u64 {
        self.allocations.iter().map(|a| a.size).sum()
    }

    pub fn set_max_allocations(&mut self, max: usize) {
        self.max_allocations = max;
    }

    pub fn get_allocations_with_high_protection(&self) -> Vec<&MemoryAllocEvent> {
        self.allocations
            .iter()
            .filter(|a| {
                let upper = a.protection.to_uppercase();
                upper.contains("READWRITEEXECUTE") || upper.contains("EXECUTEWRITECOPY")
            })
            .collect()
    }
}

#[async_trait]
impl SecurityModule for MemoryCollector {
    fn name(&self) -> &str {
        "Memory Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors memory allocation patterns and suspicious memory operations"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Memory Collector initialized");
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

    fn test_alloc(pid: u32, size: u64, protection: &str, alloc_type: &str) -> MemoryAllocEvent {
        MemoryAllocEvent {
            process_id: pid,
            base_address: 0x10000000 + (pid as u64 * 0x10000),
            size,
            protection: protection.into(),
            allocation_type: alloc_type.into(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_new_collector() {
        let collector = MemoryCollector::new(test_bus());
        assert_eq!(collector.allocation_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_capture_and_retrieve() {
        let mut collector = MemoryCollector::new(test_bus());
        collector.capture_allocation(test_alloc(100, 4096, "ReadWrite", "Commit"));
        collector.capture_allocation(test_alloc(100, 8192, "ExecuteRead", "Commit"));
        assert_eq!(collector.allocation_count(), 2);
        assert_eq!(collector.get_allocations().len(), 2);
    }

    #[test]
    fn test_get_allocations_for_process() {
        let mut collector = MemoryCollector::new(test_bus());
        collector.capture_allocation(test_alloc(100, 4096, "ReadWrite", "Commit"));
        collector.capture_allocation(test_alloc(200, 8192, "ReadWrite", "Commit"));
        collector.capture_allocation(test_alloc(100, 16384, "ExecuteRead", "Reserve"));
        let p100 = collector.get_allocations_for_process(100);
        assert_eq!(p100.len(), 2);
        let p200 = collector.get_allocations_for_process(200);
        assert_eq!(p200.len(), 1);
    }

    #[test]
    fn test_executable_allocations() {
        let mut collector = MemoryCollector::new(test_bus());
        collector.capture_allocation(test_alloc(100, 4096, "ReadWrite", "Commit"));
        collector.capture_allocation(test_alloc(100, 8192, "ExecuteReadWrite", "Code"));
        collector.capture_allocation(test_alloc(100, 16384, "NoAccess", "Reserve"));
        collector.capture_allocation(test_alloc(100, 32768, "ExecuteRead", "Commit"));
        let execs = collector.get_executable_allocations();
        assert_eq!(execs.len(), 2);
    }

    #[test]
    fn test_total_allocated_bytes() {
        let mut collector = MemoryCollector::new(test_bus());
        collector.capture_allocation(test_alloc(100, 1024, "ReadWrite", "Commit"));
        collector.capture_allocation(test_alloc(100, 2048, "ReadWrite", "Commit"));
        assert_eq!(collector.total_allocated_bytes(), 3072);
    }

    #[test]
    fn test_max_allocations_overflow() {
        let mut collector = MemoryCollector::with_max_allocations(test_bus(), 3);
        for i in 0..5 {
            collector.capture_allocation(test_alloc(i, 4096, "ReadWrite", "Commit"));
        }
        assert_eq!(collector.allocation_count(), 3);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = MemoryCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_clear() {
        let mut collector = MemoryCollector::new(test_bus());
        collector.capture_allocation(test_alloc(100, 4096, "ReadWrite", "Commit"));
        assert_eq!(collector.allocation_count(), 1);
        collector.clear();
        assert_eq!(collector.allocation_count(), 0);
    }

    #[test]
    fn test_high_protection_allocations() {
        let mut collector = MemoryCollector::new(test_bus());
        collector.capture_allocation(test_alloc(100, 4096, "ReadWriteExecute", "Commit"));
        collector.capture_allocation(test_alloc(100, 4096, "ExecuteWriteCopy", "Commit"));
        collector.capture_allocation(test_alloc(100, 4096, "ReadOnly", "Commit"));
        let high = collector.get_allocations_with_high_protection();
        assert_eq!(high.len(), 2);
    }
}
