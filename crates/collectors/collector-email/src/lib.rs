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
pub enum EmailError {
    #[error("Email collector not running")]
    NotRunning,
    #[error("Collector error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum EmailEventType {
    EmailSent,
    EmailReceived,
    AttachmentOpened,
    AttachmentBlocked,
    PhishingDetected,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmailEvent {
    pub client: String,
    pub event_type: EmailEventType,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

pub struct EmailCollector {
    _bus: EventBus,
    config: ModuleConfig,
    status: ModuleStatus,
    start_time: Option<Instant>,
    events_processed: u64,
    errors: u64,
    events: Vec<EmailEvent>,
    blocked_extensions: Vec<String>,
    blocked_content_types: Vec<String>,
    phishing_keywords: Vec<String>,
}

impl EmailCollector {
    pub fn new(bus: EventBus) -> Self {
        Self {
            _bus: bus,
            config: ModuleConfig::default(),
            status: ModuleStatus::Uninitialized,
            start_time: None,
            events_processed: 0,
            errors: 0,
            events: Vec::new(),
            blocked_extensions: vec![
                ".exe".into(), ".bat".into(), ".cmd".into(), ".ps1".into(),
                ".vbs".into(), ".js".into(), ".wsf".into(), ".scr".into(), ".pif".into(),
            ],
            blocked_content_types: vec![
                "application/x-msdownload".into(),
                "application/x-bat".into(),
                "application/x-cmd".into(),
            ],
            phishing_keywords: vec![
                "verify your account".into(),
                "urgent action required".into(),
                "suspended".into(),
                "click here immediately".into(),
            ],
        }
    }

    pub fn start(&mut self) -> std::result::Result<(), EmailError> {
        self.start_time = Some(Instant::now());
        self.status = ModuleStatus::Running;
        info!("Email Collector started");
        Ok(())
    }

    pub fn stop(&mut self) -> std::result::Result<(), EmailError> {
        self.status = ModuleStatus::Stopped;
        info!(
            "Email Collector stopped. Processed {} events",
            self.events_processed
        );
        Ok(())
    }

    pub fn collect_events(&mut self) -> Vec<EmailEvent> {
        let events: Vec<EmailEvent> = self.events.drain(..).collect();
        self.events_processed += events.len() as u64;
        events
    }

    pub fn record_sent(&mut self, client: &str, details: &str) {
        self.events.push(EmailEvent {
            client: client.into(),
            event_type: EmailEventType::EmailSent,
            details: details.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn record_received(&mut self, client: &str, details: &str) {
        self.events.push(EmailEvent {
            client: client.into(),
            event_type: EmailEventType::EmailReceived,
            details: details.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn check_attachment(&self, filename: &str, content_type: &str) -> bool {
        let lower_name = filename.to_lowercase();
        let lower_ct = content_type.to_lowercase();
        if self.blocked_extensions.iter().any(|ext| lower_name.ends_with(ext.as_str())) {
            return false;
        }
        if self.blocked_content_types.iter().any(|ct| lower_ct.contains(ct.as_str())) {
            return false;
        }
        true
    }

    pub fn check_phishing(&self, body: &str) -> bool {
        let lower_body = body.to_lowercase();
        self.phishing_keywords.iter().any(|kw| lower_body.contains(kw.as_str()))
    }

    pub fn record_attachment_opened(&mut self, client: &str, filename: &str) {
        self.events.push(EmailEvent {
            client: client.into(),
            event_type: EmailEventType::AttachmentOpened,
            details: format!("Attachment opened: {}", filename),
            timestamp: Utc::now(),
        });
    }

    pub fn record_attachment_blocked(&mut self, client: &str, filename: &str, reason: &str) {
        self.events.push(EmailEvent {
            client: client.into(),
            event_type: EmailEventType::AttachmentBlocked,
            details: format!("Attachment blocked: {} ({})", filename, reason),
            timestamp: Utc::now(),
        });
    }

    pub fn record_phishing_detected(&mut self, client: &str, details: &str) {
        self.events.push(EmailEvent {
            client: client.into(),
            event_type: EmailEventType::PhishingDetected,
            details: details.into(),
            timestamp: Utc::now(),
        });
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn is_collecting(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    pub fn get_events(&self) -> &[EmailEvent] {
        &self.events
    }
}

#[async_trait]
impl SecurityModule for EmailCollector {
    fn name(&self) -> &str {
        "Email Collector"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        "Monitors email client activity and scans attachments"
    }

    async fn initialize(
        &mut self,
        config: ModuleConfig,
    ) -> std::result::Result<(), Box<dyn Error + Send + Sync>> {
        self.config = config;
        self.status = ModuleStatus::Initialized;
        info!("Email Collector initialized");
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
        let collector = EmailCollector::new(test_bus());
        assert_eq!(collector.event_count(), 0);
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_attachment_check_safe() {
        let collector = EmailCollector::new(test_bus());
        assert!(collector.check_attachment("document.pdf", "application/pdf"));
        assert!(collector.check_attachment("image.png", "image/png"));
        assert!(collector.check_attachment("spreadsheet.xlsx", "application/vnd.ms-excel"));
    }

    #[test]
    fn test_attachment_check_blocked() {
        let collector = EmailCollector::new(test_bus());
        assert!(!collector.check_attachment("malware.exe", "application/x-msdownload"));
        assert!(!collector.check_attachment("script.ps1", "text/plain"));
        assert!(!collector.check_attachment("payload.bat", "application/x-bat"));
        assert!(!collector.check_attachment("virus.scr", "application/octet-stream"));
    }

    #[test]
    fn test_phishing_detection() {
        let collector = EmailCollector::new(test_bus());
        assert!(collector.check_phishing("Please verify your account immediately"));
        assert!(collector.check_phishing("URGENT ACTION REQUIRED on your account"));
        assert!(!collector.check_phishing("Meeting scheduled for tomorrow at 3pm"));
    }

    #[test]
    fn test_record_events() {
        let mut collector = EmailCollector::new(test_bus());
        collector.record_sent("Outlook", "Sent email to admin@corp.com");
        collector.record_received("Outlook", "Received email from vendor@test.com");
        assert_eq!(collector.event_count(), 2);
        let events = collector.collect_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, EmailEventType::EmailSent);
        assert_eq!(events[1].event_type, EmailEventType::EmailReceived);
    }

    #[test]
    fn test_start_stop() {
        let mut collector = EmailCollector::new(test_bus());
        assert!(collector.start().is_ok());
        assert!(collector.is_collecting());
        assert!(collector.stop().is_ok());
        assert!(!collector.is_collecting());
    }

    #[test]
    fn test_record_attachment_and_phishing() {
        let mut collector = EmailCollector::new(test_bus());
        collector.record_attachment_opened("Outlook", "report.xlsx");
        collector.record_attachment_blocked("Thunderbird", "payload.exe", "blocked extension");
        collector.record_phishing_detected("Outlook", "Suspicious link detected");
        let events = collector.collect_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, EmailEventType::AttachmentOpened);
        assert_eq!(events[1].event_type, EmailEventType::AttachmentBlocked);
        assert_eq!(events[2].event_type, EmailEventType::PhishingDetected);
    }
}
