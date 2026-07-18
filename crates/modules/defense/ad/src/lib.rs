pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdError {
    #[error("AD event processing failed: {0}")]
    ProcessingFailed(String),
    #[error("Unknown AD event type")]
    UnknownEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum AdEventType {
    UserCreated,
    GroupModified,
    GpoChanged,
    Kerberoasting,
    DcsyncAttempt,
    GoldenTicket,
    SilverTicket,
    PasswordSpray,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdEvent {
    pub event_type: AdEventType,
    pub object: String,
    pub details: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDetection {
    pub detection_type: AdEventType,
    pub description: String,
    pub severity: EventSeverity,
    pub source_user: Option<String>,
    pub target_user: Option<String>,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosServiceTicket {
    pub service_name: String,
    pub requesting_user: String,
    pub encryption_type: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcSyncRequest {
    pub source_user: String,
    pub target_user: String,
    pub attributes_requested: Vec<String>,
    pub source_ip: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordSprayRecord {
    pub source_ip: String,
    pub failed_count: u32,
    pub unique_users: u32,
    pub window_secs: u64,
    pub timestamp: DateTime<Utc>,
}

pub struct AdMonitor {
    detections: Vec<AdDetection>,
    event_history: Vec<AdEvent>,
    suspicious_service_tickets: Vec<KerberosServiceTicket>,
    dcsync_attempts: Vec<DcSyncRequest>,
    password_spray_records: Vec<PasswordSprayRecord>,
    user_creation_events: HashMap<String, DateTime<Utc>>,
    group_modifications: HashMap<String, u32>,
    gpo_changes: Vec<AdEvent>,
}

impl AdMonitor {
    pub fn new() -> Self {
        info!("Initializing Active Directory Security monitor");
        Self {
            detections: Vec::new(),
            event_history: Vec::new(),
            suspicious_service_tickets: Vec::new(),
            dcsync_attempts: Vec::new(),
            password_spray_records: Vec::new(),
            user_creation_events: HashMap::new(),
            group_modifications: HashMap::new(),
            gpo_changes: Vec::new(),
        }
    }

    pub fn analyze_event(&mut self, event: &AdEvent) -> Vec<AdDetection> {
        self.event_history.push(event.clone());
        let mut detections = Vec::new();

        match event.event_type {
            AdEventType::UserCreated => {
                info!(object = %event.object, "AD user creation detected");
                self.user_creation_events.insert(event.object.clone(), event.timestamp);
            }
            AdEventType::GroupModified => {
                warn!(object = %event.object, "AD group modification detected");
                let count = self.group_modifications.entry(event.object.clone()).or_insert(0);
                *count += 1;
                if *count > 3 {
                    detections.push(AdDetection {
                        detection_type: AdEventType::GroupModified,
                        description: format!("Excessive group modifications for {}", event.object),
                        severity: event.severity,
                        source_user: None,
                        target_user: None,
                        confidence: 0.8,
                        timestamp: event.timestamp,
                    });
                }
            }
            AdEventType::GpoChanged => {
                warn!(object = %event.object, "GPO change detected");
                self.gpo_changes.push(event.clone());
            }
            AdEventType::Kerberoasting => {
                warn!(object = %event.object, "Kerberoasting activity detected");
                detections.push(AdDetection {
                    detection_type: AdEventType::Kerberoasting,
                    description: format!("Kerberoasting targeting {}", event.object),
                    severity: EventSeverity::Critical,
                    source_user: None,
                    target_user: None,
                    confidence: 0.95,
                    timestamp: event.timestamp,
                });
            }
            AdEventType::DcsyncAttempt => {
                warn!(object = %event.object, "DCSync attempt detected");
                detections.push(AdDetection {
                    detection_type: AdEventType::DcsyncAttempt,
                    description: format!("DCSync attack targeting {}", event.object),
                    severity: EventSeverity::Critical,
                    source_user: None,
                    target_user: None,
                    confidence: 0.98,
                    timestamp: event.timestamp,
                });
            }
            AdEventType::GoldenTicket => {
                warn!(object = %event.object, "Golden Ticket detected");
                detections.push(AdDetection {
                    detection_type: AdEventType::GoldenTicket,
                    description: format!("Golden Ticket authentication from {}", event.object),
                    severity: EventSeverity::Critical,
                    source_user: None,
                    target_user: None,
                    confidence: 0.99,
                    timestamp: event.timestamp,
                });
            }
            AdEventType::SilverTicket => {
                warn!(object = %event.object, "Silver Ticket detected");
                detections.push(AdDetection {
                    detection_type: AdEventType::SilverTicket,
                    description: format!("Silver Ticket for service {}", event.object),
                    severity: EventSeverity::High,
                    source_user: None,
                    target_user: None,
                    confidence: 0.95,
                    timestamp: event.timestamp,
                });
            }
            AdEventType::PasswordSpray => {
                warn!(object = %event.object, "Password spray detected");
                detections.push(AdDetection {
                    detection_type: AdEventType::PasswordSpray,
                    description: format!("Password spray from {}", event.object),
                    severity: EventSeverity::High,
                    source_user: None,
                    target_user: None,
                    confidence: 0.85,
                    timestamp: event.timestamp,
                });
            }
        }

        self.detections.extend(detections.clone());
        detections
    }

    pub fn detect_kerberoasting(&mut self, service_name: &str, requesting_user: &str) -> Vec<AdDetection> {
        let ticket = KerberosServiceTicket {
            service_name: service_name.to_string(),
            requesting_user: requesting_user.to_string(),
            encryption_type: "RC4".to_string(),
            timestamp: Utc::now(),
        };
        self.suspicious_service_tickets.push(ticket);

        let mut detections = Vec::new();

        let rc4_requests = self.suspicious_service_tickets
            .iter()
            .filter(|t| t.requesting_user == requesting_user && t.encryption_type == "RC4")
            .count();

        if rc4_requests > 5 {
            let detection = AdDetection {
                detection_type: AdEventType::Kerberoasting,
                description: format!(
                    "User {} requested {} RC4-encrypted service tickets ({} total) - Kerberoasting suspected",
                    requesting_user, rc4_requests, self.suspicious_service_tickets.len()
                ),
                severity: EventSeverity::Critical,
                source_user: Some(requesting_user.to_string()),
                target_user: Some(service_name.to_string()),
                confidence: 0.95,
                timestamp: Utc::now(),
            };
            detections.push(detection.clone());
            self.detections.push(detection);
        }

        if let Some(first) = self.suspicious_service_tickets.first() {
            if self.suspicious_service_tickets.len() > 10 {
                let time_window = Utc::now()
                    .signed_duration_since(first.timestamp)
                    .num_seconds();
                if time_window < 60 {
                    let detection = AdDetection {
                        detection_type: AdEventType::Kerberoasting,
                        description: format!(
                            "Burst of {} service ticket requests in {} seconds - automated Kerberoasting",
                            self.suspicious_service_tickets.len(), time_window
                        ),
                        severity: EventSeverity::Critical,
                        source_user: Some(requesting_user.to_string()),
                        target_user: Some(service_name.to_string()),
                        confidence: 0.98,
                        timestamp: Utc::now(),
                    };
                    detections.push(detection.clone());
                    self.detections.push(detection);
                }
            }
        }

        detections
    }

    pub fn detect_dcsync(&mut self, source_user: &str, target_user: &str) -> Vec<AdDetection> {
        let request = DcSyncRequest {
            source_user: source_user.to_string(),
            target_user: target_user.to_string(),
            attributes_requested: vec![
                "dBCSPwd".to_string(),
                "unicodePwd".to_string(),
                "ntPwdHistory".to_string(),
                "supplementalCredentials".to_string(),
            ],
            source_ip: None,
            timestamp: Utc::now(),
        };
        self.dcsync_attempts.push(request);

        let mut detections = Vec::new();

        let attempts_from_source = self.dcsync_attempts
            .iter()
            .filter(|r| r.source_user == source_user)
            .count();

        let sensitive_attrs = ["dBCSPwd", "unicodePwd", "ntPwdHistory", "supplementalCredentials"];
        let last_request = self.dcsync_attempts.last().unwrap();
        let has_sensitive_attrs = last_request.attributes_requested
            .iter()
            .any(|a| sensitive_attrs.contains(&a.as_str()));

        if has_sensitive_attrs && attempts_from_source > 0 {
            let detection = AdDetection {
                detection_type: AdEventType::DcsyncAttempt,
                description: format!(
                    "User {} attempted DCSync against {} requesting credential attributes (attempt #{})",
                    source_user, target_user, attempts_from_source
                ),
                severity: EventSeverity::Critical,
                source_user: Some(source_user.to_string()),
                target_user: Some(target_user.to_string()),
                confidence: 0.98,
                timestamp: Utc::now(),
            };
            detections.push(detection.clone());
            self.detections.push(detection);
        }

        if attempts_from_source > 3 {
            let detection = AdDetection {
                detection_type: AdEventType::DcsyncAttempt,
                description: format!(
                    "Repeated DCSync attempts from {} ({} total attempts)",
                    source_user, attempts_from_source
                ),
                severity: EventSeverity::Critical,
                source_user: Some(source_user.to_string()),
                target_user: Some(target_user.to_string()),
                confidence: 0.99,
                timestamp: Utc::now(),
            };
            detections.push(detection.clone());
            self.detections.push(detection);
        }

        detections
    }

    pub fn detect_password_spray(&mut self, source_ip: &str, failed_count: u32) -> Vec<AdDetection> {
        let record = PasswordSprayRecord {
            source_ip: source_ip.to_string(),
            failed_count,
            unique_users: failed_count,
            window_secs: 300,
            timestamp: Utc::now(),
        };
        self.password_spray_records.push(record);

        let mut detections = Vec::new();

        let total_failures: u32 = self.password_spray_records
            .iter()
            .filter(|r| r.source_ip == source_ip)
            .map(|r| r.failed_count)
            .sum();

        if failed_count >= 10 {
            let detection = AdDetection {
                detection_type: AdEventType::PasswordSpray,
                description: format!(
                    "High volume of failed logins from {} ({} failures) - password spray suspected",
                    source_ip, failed_count
                ),
                severity: EventSeverity::High,
                source_user: None,
                target_user: None,
                confidence: 0.85,
                timestamp: Utc::now(),
            };
            detections.push(detection.clone());
            self.detections.push(detection);
        }

        if total_failures > 50 {
            let detection = AdDetection {
                detection_type: AdEventType::PasswordSpray,
                description: format!(
                    "Cumulative {} failed logins from {} - persistent password spray",
                    total_failures, source_ip
                ),
                severity: EventSeverity::Critical,
                source_user: None,
                target_user: None,
                confidence: 0.92,
                timestamp: Utc::now(),
            };
            detections.push(detection.clone());
            self.detections.push(detection);
        }

        detections
    }

    pub fn get_all_detections(&self) -> &[AdDetection] {
        &self.detections
    }

    pub fn get_event_history(&self) -> &[AdEvent] {
        &self.event_history
    }
}

impl Default for AdMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: AdEventType, object: &str, details: &str) -> AdEvent {
        AdEvent {
            event_type,
            object: object.to_string(),
            details: details.to_string(),
            severity: EventSeverity::Medium,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_ad_monitor_new() {
        let monitor = AdMonitor::new();
        assert!(monitor.get_all_detections().is_empty());
        assert!(monitor.get_event_history().is_empty());
    }

    #[test]
    fn test_analyze_event_user_created() {
        let mut monitor = AdMonitor::new();
        let event = make_event(AdEventType::UserCreated, "svc_backup", "New service account created");
        let detections = monitor.analyze_event(&event);
        assert!(detections.is_empty());
        assert_eq!(monitor.get_event_history().len(), 1);
        assert!(monitor.user_creation_events.contains_key("svc_backup"));
    }

    #[test]
    fn test_analyze_event_kerberoasting() {
        let mut monitor = AdMonitor::new();
        let event = make_event(AdEventType::Kerberoasting, "SQLService", "RC4 ticket requested");
        let detections = monitor.analyze_event(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, AdEventType::Kerberoasting);
        assert_eq!(detections[0].severity, EventSeverity::Critical);
    }

    #[test]
    fn test_analyze_event_golden_ticket() {
        let mut monitor = AdMonitor::new();
        let event = make_event(AdEventType::GoldenTicket, "attacker@CORP.LOCAL", "KRBTGT ticket forgery");
        let detections = monitor.analyze_event(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, AdEventType::GoldenTicket);
        assert!(detections[0].confidence > 0.95);
    }

    #[test]
    fn test_analyze_event_silver_ticket() {
        let mut monitor = AdMonitor::new();
        let event = make_event(AdEventType::SilverTicket, "HTTP/web01.corp.local", "Forged service ticket");
        let detections = monitor.analyze_event(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, AdEventType::SilverTicket);
    }

    #[test]
    fn test_analyze_event_group_modified_threshold() {
        let mut monitor = AdMonitor::new();
        for _ in 0..4 {
            let event = make_event(AdEventType::GroupModified, "Domain Admins", "Member added");
            let detections = monitor.analyze_event(&event);
            if monitor.group_modifications["Domain Admins"] > 3 {
                assert_eq!(detections.len(), 1);
                assert_eq!(detections[0].detection_type, AdEventType::GroupModified);
                return;
            }
        }
        panic!("Should have triggered group modification detection");
    }

    #[test]
    fn test_detect_kerberoasting_high_volume() {
        let mut monitor = AdMonitor::new();
        for _ in 0..6 {
            let detections = monitor.detect_kerberoasting("SQLService", "attacker");
            if !detections.is_empty() {
                assert_eq!(detections[0].detection_type, AdEventType::Kerberoasting);
                assert_eq!(detections[0].severity, EventSeverity::Critical);
                return;
            }
        }
        panic!("Should have triggered kerberoasting detection");
    }

    #[test]
    fn test_detect_dcsync() {
        let mut monitor = AdMonitor::new();
        let detections = monitor.detect_dcsync("compromised_user", "Administrator");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, AdEventType::DcsyncAttempt);
        assert!(detections[0].target_user.is_some());
    }

    #[test]
    fn test_detect_dcsync_repeated() {
        let mut monitor = AdMonitor::new();
        for _ in 0..5 {
            monitor.detect_dcsync("attacker", "KRBTGT");
        }
        let detections = monitor.detect_dcsync("attacker", "Administrator");
        assert!(detections.len() >= 1);
        assert!(monitor.get_all_detections().len() >= 2);
    }

    #[test]
    fn test_detect_password_spray() {
        let mut monitor = AdMonitor::new();
        let detections = monitor.detect_password_spray("10.0.0.50", 15);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, AdEventType::PasswordSpray);
    }

    #[test]
    fn test_detect_password_spray_cumulative() {
        let mut monitor = AdMonitor::new();
        for _ in 0..6 {
            monitor.detect_password_spray("10.0.0.50", 10);
        }
        assert!(monitor.get_all_detections().len() >= 2);
    }

    #[test]
    fn test_analyze_event_dcsync_direct() {
        let mut monitor = AdMonitor::new();
        let event = make_event(AdEventType::DcsyncAttempt, "Administrator", "Password attributes requested");
        let detections = monitor.analyze_event(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, AdEventType::DcsyncAttempt);
    }
}
