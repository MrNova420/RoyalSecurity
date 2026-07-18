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

pub struct DnsCollector {
    _bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    captures: Vec<CapturedDns>,
    capture_config: DnsCaptureConfig,
}

impl DnsCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            captures: Vec::new(),
            capture_config: DnsCaptureConfig::default(),
        }
    }

    pub fn with_config(bus: EventBus, capture_config: DnsCaptureConfig) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            captures: Vec::new(),
            capture_config,
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), DnsCollectorError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!(
            "DNS Collector started with {} captures",
            self.captures.len()
        );
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), DnsCollectorError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "DNS Collector stopped. Captured {} queries",
            self.captures.len()
        );
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
                self.captures.push(dns);
            }
        }
    }

    pub fn get_captures(&self) -> Vec<&CapturedDns> {
        self.captures.iter().collect()
    }

    pub fn capture_count(&self) -> usize {
        self.captures.len()
    }

    pub fn clear(&mut self) {
        self.captures.clear();
    }

    pub fn get_captures_for_process(&self, process_name: &str) -> Vec<&CapturedDns> {
        self.captures
            .iter()
            .filter(|c| c.process_name == process_name)
            .collect()
    }

    pub fn get_captures_by_domain(&self, domain: &str) -> Vec<&CapturedDns> {
        self.captures
            .iter()
            .filter(|c| c.query.contains(domain))
            .collect()
    }

    pub fn set_filter_domains(&mut self, domains: Vec<String>) {
        self.capture_config.filter_domains = domains;
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn update_config(&mut self, config: DnsCaptureConfig) {
        self.capture_config = config;
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
        "Captures DNS queries and responses for analysis"
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
}
