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
    bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    requests: Vec<HttpEvent>,
    max_requests: usize,
}

impl HttpCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            requests: Vec::new(),
            max_requests: 100_000,
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
}
