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
use std::sync::Arc;

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
    pub region_type: String,
    pub suspicious: bool,
    pub suspicion_reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub struct MemoryCollector {
    bus: Arc<EventBus>,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    allocations: Vec<MemoryAllocEvent>,
    max_allocations: usize,
}

unsafe impl Send for MemoryCollector {}
unsafe impl Sync for MemoryCollector {}

impl MemoryCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus: Arc::new(bus),
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

    #[cfg(target_os = "windows")]
    pub fn scan_process_memory(&mut self, pid: u32) -> Vec<MemoryAllocEvent> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY};
        use windows::Win32::Foundation::CloseHandle;
        use std::ffi::c_void;

        let mut results = Vec::new();

        unsafe {
            let process_handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            ) {
                Ok(handle) => handle,
                Err(e) => {
                    warn!("Failed to open process {} for memory scan: {}", pid, e);
                    return results;
                }
            };

            let mut address = 0usize;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            while VirtualQueryEx(
                process_handle,
                Some(address as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) > 0
            {
                let region_size = mbi.RegionSize;
                let base = mbi.BaseAddress as u64;
                let protect = mbi.Protect;
                let state = mbi.State;

                let protection_str = match protect {
                    p if p == PAGE_READWRITE => "ReadWrite".into(),
                    p if p == PAGE_EXECUTE_READWRITE => "ExecuteReadWrite".into(),
                    p if p == PAGE_EXECUTE_READ => "ExecuteRead".into(),
                    p if p == PAGE_EXECUTE => "Execute".into(),
                    p if p == PAGE_EXECUTE_WRITECOPY => "ExecuteWriteCopy".into(),
                    p if p == PAGE_WRITECOPY => "WriteCopy".into(),
                    _ => format!("0x{:X}", protect.0),
                };

                let state_str = if state == MEM_COMMIT {
                    "Commit"
                } else if state == MEM_RESERVE {
                    "Reserve"
                } else {
                    "Free"
                };

                let mut suspicious = false;
                let mut suspicion_reason = None;

                if protect == PAGE_EXECUTE_READWRITE {
                    suspicious = true;
                    suspicion_reason = Some("RWX memory region (common in process injection)".into());
                }

                if state == MEM_COMMIT && region_size > 100 * 1024 * 1024 {
                    suspicious = true;
                    suspicion_reason = Some(format!("Oversized committed region: {} bytes", region_size));
                }

                let event = MemoryAllocEvent {
                    process_id: pid,
                    base_address: base,
                    size: region_size as u64,
                    protection: protection_str,
                    allocation_type: state_str.into(),
                    region_type: "Unknown".into(),
                    suspicious,
                    suspicion_reason,
                    timestamp: Utc::now(),
                };

                results.push(event);

                let base_addr = mbi.BaseAddress as usize;
                if let Some(next) = base_addr.checked_add(region_size) {
                    address = next;
                } else {
                    break;
                }
            }

            let _ = CloseHandle(process_handle);
        }

        self.events_processed += results.len() as u64;
        self.allocations.extend(results.clone());
        results
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_process_memory(&mut self, _pid: u32) -> Vec<MemoryAllocEvent> {
        Vec::new()
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

    pub fn get_suspicious_allocations(&self) -> Vec<&MemoryAllocEvent> {
        self.allocations.iter().filter(|a| a.suspicious).collect()
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
        "0.2.0"
    }
    fn description(&self) -> &str {
        "Real memory region scanning using VirtualQueryEx for injection detection"
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
            region_type: "Unknown".into(),
            suspicious: false,
            suspicion_reason: None,
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
    fn test_suspicious_detection() {
        let mut collector = MemoryCollector::new(test_bus());
        let mut suspicious = test_alloc(100, 4096, "ReadWriteExecute", "Commit");
        suspicious.suspicious = true;
        suspicious.suspicion_reason = Some("RWX region".into());
        collector.capture_allocation(suspicious);
        collector.capture_allocation(test_alloc(100, 4096, "ReadWrite", "Commit"));

        let sus = collector.get_suspicious_allocations();
        assert_eq!(sus.len(), 1);
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

    #[cfg(target_os = "windows")]
    #[test]
    fn test_scan_process_memory() {
        let mut collector = MemoryCollector::new(test_bus());
        let results = collector.scan_process_memory(std::process::id());
        assert!(!results.is_empty());
    }
}
