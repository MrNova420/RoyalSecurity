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
pub enum BootError {
    #[error("Boot collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum BootEventType {
    SystemBoot,
    SystemShutdown,
    BootConfigChanged,
    DriverLoaded,
    StartupItemAdded,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootEvent {
    pub event_type: BootEventType,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

pub struct BootCollector {
    bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    events: Vec<BootEvent>,
    boot_times: Vec<DateTime<Utc>>,
    boot_count: u64,
}

impl BootCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            events: Vec::new(),
            boot_times: Vec::new(),
            boot_count: 0,
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), BootError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("Boot Collector started");
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), BootError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Boot Collector stopped. Processed {} events",
            self.events_processed
        );
        Ok(())
    }

    pub fn collect_events(&mut self) -> Vec<BootEvent> {
        let events: Vec<BootEvent> = self.events.drain(..).collect();
        self.events_processed += events.len() as u64;
        events
    }

    pub fn record_boot_time(&mut self) {
        let now = Utc::now();
        self.boot_times.push(now);
        self.boot_count += 1;
        self.events.push(BootEvent {
            event_type: BootEventType::SystemBoot,
            details: format!("System boot #{} recorded", self.boot_count),
            timestamp: now,
        });
    }

    pub fn record_shutdown(&mut self, reason: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::SystemShutdown,
            details: reason.to_string(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_config_change(&mut self, details: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::BootConfigChanged,
            details: details.to_string(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_driver_loaded(&mut self, driver_name: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::DriverLoaded,
            details: format!("Driver loaded: {}", driver_name),
            timestamp: Utc::now(),
        });
    }

    pub fn record_startup_item(&mut self, item_name: &str) {
        self.events.push(BootEvent {
            event_type: BootEventType::StartupItemAdded,
            details: format!("Startup item added: {}", item_name),
            timestamp: Utc::now(),
        });
    }

    pub fn get_boot_history(&self) -> &[DateTime<Utc>] {
        &self.boot_times
    }

    pub fn boot_count(&self) -> u64 {
        self.boot_count
    }

    pub fn get_events(&self) -> &[BootEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn last_boot_time(&self) -> Option<DateTime<Utc>> {
        self.boot_times.last().copied()
    }

    pub fn time_since_last_boot(&self) -> Option<std::time::Duration> {
        self.boot_times.last().map(|t| Utc::now() - *t).map(|d| {
            std::time::Duration::from_millis(d.num_milliseconds() as u64)
        })
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }
}

#[async_trait]
impl SecurityModule for BootCollector {
    fn name(&self) -> &str {
        "Boot Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Collects boot events, startup items, and boot time analysis"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Boot Collector initialized");
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
        let collector = BootCollector::new(test_bus());
        assert_eq!(collector.boot_count(), 0);
        assert!(!collector.is_collecting());
        assert!(collector.get_boot_history().is_empty());
    }

    #[test]
    fn test_record_boot_time() {
        let mut collector = BootCollector::new(test_bus());
        collector.record_boot_time();
        assert_eq!(collector.boot_count(), 1);
        assert_eq!(collector.get_boot_history().len(), 1);
        collector.record_boot_time();
        assert_eq!(collector.boot_count(), 2);
    }

    #[test]
    fn test_collect_events() {
        let mut collector = BootCollector::new(test_bus());
        collector.record_boot_time();
        collector.record_shutdown("user logout");
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, BootEventType::SystemBoot);
        assert_eq!(events[1].event_type, BootEventType::SystemShutdown);
        assert!(collector.collect_events().is_empty());
    }

    #[test]
    fn test_record_various_events() {
        let mut collector = BootCollector::new(test_bus());
        collector.record_config_change("BCD modified");
        collector.record_driver_loaded("nvlddmkm.sys");
        collector.record_startup_item("SecurityAgent");
        let events = collector.collect_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, BootEventType::BootConfigChanged);
        assert_eq!(events[1].event_type, BootEventType::DriverLoaded);
        assert_eq!(events[2].event_type, BootEventType::StartupItemAdded);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = BootCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_boot_history_and_last_boot() {
        let mut collector = BootCollector::new(test_bus());
        assert!(collector.last_boot_time().is_none());
        assert!(collector.time_since_last_boot().is_none());
        collector.record_boot_time();
        assert!(collector.last_boot_time().is_some());
        assert!(collector.time_since_last_boot().is_some());
    }

    #[test]
    fn test_event_count() {
        let mut collector = BootCollector::new(test_bus());
        assert_eq!(collector.event_count(), 0);
        collector.record_boot_time();
        collector.record_shutdown("update");
        assert_eq!(collector.event_count(), 2);
    }
}
