pub mod prelude;

use royalsecurity_common::types::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{warn, info};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("Certificate check failed: {0}")]
    CheckFailed(String),
    #[error("Pinning violation: {0}")]
    PinningViolation(String),
    #[error("Certificate not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CertAlertType {
    RogueCert,
    ExpiredCert,
    SelfSigned,
    PinningViolation,
    MitmIndicator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint: String,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertAlert {
    pub alert_type: CertAlertType,
    pub certificate_subject: String,
    pub certificate_issuer: String,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningEntry {
    pub domain: String,
    pub allowed_fingerprints: Vec<String>,
    pub created_at: DateTime<Utc>,
}

pub struct CertificateMonitor {
    trusted_certs: HashMap<String, CertInfo>,
    untrusted_certs: Vec<CertInfo>,
    pinned_domains: HashMap<String, PinningEntry>,
    alerts: Vec<CertAlert>,
    known_rogue_issuers: Vec<String>,
    cert_history: Vec<(String, bool, DateTime<Utc>)>,
}

impl CertificateMonitor {
    pub fn new() -> Self {
        info!("Initializing Certificate Trust monitor");
        Self {
            trusted_certs: HashMap::new(),
            untrusted_certs: Vec::new(),
            pinned_domains: HashMap::new(),
            alerts: Vec::new(),
            known_rogue_issuers: vec![
                "Fake CA".to_string(),
                "Rogue Root".to_string(),
                "CompromisedIssuer".to_string(),
            ],
            cert_history: Vec::new(),
        }
    }

    pub fn check_certificate(&mut self, cert: &CertInfo) -> Vec<CertAlert> {
        let mut alerts = Vec::new();

        self.cert_history.push((cert.fingerprint.clone(), cert.trusted, Utc::now()));

        if cert.not_before > Utc::now() {
            let alert = CertAlert {
                alert_type: CertAlertType::RogueCert,
                certificate_subject: cert.subject.clone(),
                certificate_issuer: cert.issuer.clone(),
                message: format!("Certificate '{}' has future not_before date", cert.subject),
                severity: EventSeverity::High,
                timestamp: Utc::now(),
            };
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        if cert.not_after < Utc::now() {
            let alert = CertAlert {
                alert_type: CertAlertType::ExpiredCert,
                certificate_subject: cert.subject.clone(),
                certificate_issuer: cert.issuer.clone(),
                message: format!("Certificate '{}' expired on {}", cert.subject, cert.not_after),
                severity: EventSeverity::Medium,
                timestamp: Utc::now(),
            };
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        if cert.subject == cert.issuer {
            let alert = CertAlert {
                alert_type: CertAlertType::SelfSigned,
                certificate_subject: cert.subject.clone(),
                certificate_issuer: cert.issuer.clone(),
                message: format!("Self-signed certificate detected: {}", cert.subject),
                severity: EventSeverity::Medium,
                timestamp: Utc::now(),
            };
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        if self.known_rogue_issuers.iter().any(|r| cert.issuer.contains(r)) {
            let alert = CertAlert {
                alert_type: CertAlertType::RogueCert,
                certificate_subject: cert.subject.clone(),
                certificate_issuer: cert.issuer.clone(),
                message: format!(
                    "Certificate '{}' issued by known rogue CA '{}'",
                    cert.subject, cert.issuer
                ),
                severity: EventSeverity::Critical,
                timestamp: Utc::now(),
            };
            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        if !cert.trusted {
            self.untrusted_certs.push(cert.clone());
        }

        alerts
    }

    pub fn add_trusted(&mut self, fingerprint: String) {
        info!(fingerprint = %fingerprint, "Adding trusted certificate fingerprint");
        let cert = CertInfo {
            subject: "Trusted".to_string(),
            issuer: "Trusted CA".to_string(),
            serial: String::new(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            fingerprint: fingerprint.clone(),
            trusted: true,
        };
        self.trusted_certs.insert(fingerprint, cert);
    }

    pub fn register_trusted_cert(&mut self, cert: CertInfo) {
        let fp = cert.fingerprint.clone();
        info!(subject = %cert.subject, "Registering trusted certificate");
        self.trusted_certs.insert(fp, cert);
    }

    pub fn check_pinning(&mut self, domain: &str, cert_fingerprint: &str) -> bool {
        if let Some(entry) = self.pinned_domains.get(domain) {
            let is_pinned = entry.allowed_fingerprints.iter().any(|fp| fp == cert_fingerprint);

            if !is_pinned {
                let alert = CertAlert {
                    alert_type: CertAlertType::PinningViolation,
                    certificate_subject: domain.to_string(),
                    certificate_issuer: "Unknown".to_string(),
                    message: format!(
                        "Certificate pinning violation for '{}': fingerprint {} not in allowed list",
                        domain, cert_fingerprint
                    ),
                    severity: EventSeverity::Critical,
                    timestamp: Utc::now(),
                };
                warn!(domain = %domain, "Certificate pinning violation");
                self.alerts.push(alert);
            }

            is_pinned
        } else {
            self.pinned_domains.insert(domain.to_string(), PinningEntry {
                domain: domain.to_string(),
                allowed_fingerprints: vec![cert_fingerprint.to_string()],
                created_at: Utc::now(),
            });
            true
        }
    }

    pub fn add_pinning(&mut self, domain: &str, fingerprint: &str) {
        let entry = self.pinned_domains
            .entry(domain.to_string())
            .or_insert_with(|| PinningEntry {
                domain: domain.to_string(),
                allowed_fingerprints: Vec::new(),
                created_at: Utc::now(),
            });
        entry.allowed_fingerprints.push(fingerprint.to_string());
    }

    pub fn detect_mitm_indicator(&mut self, domain: &str, expected_fingerprint: &str, observed_fingerprint: &str) -> bool {
        if expected_fingerprint != observed_fingerprint {
            let alert = CertAlert {
                alert_type: CertAlertType::MitmIndicator,
                certificate_subject: domain.to_string(),
                certificate_issuer: "Unknown".to_string(),
                message: format!(
                    "Possible MITM for '{}': expected fingerprint {} but observed {}",
                    domain, expected_fingerprint, observed_fingerprint
                ),
                severity: EventSeverity::Critical,
                timestamp: Utc::now(),
            };
            warn!(domain = %domain, "MITM indicator detected");
            self.alerts.push(alert);
            return true;
        }
        false
    }

    pub fn get_untrusted_certs(&self) -> &[CertInfo] {
        &self.untrusted_certs
    }

    pub fn get_alerts(&self) -> &[CertAlert] {
        &self.alerts
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }
}

impl Default for CertificateMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(subject: &str, issuer: &str, trusted: bool) -> CertInfo {
        CertInfo {
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            serial: "001".to_string(),
            not_before: Utc::now() - chrono::Duration::days(30),
            not_after: Utc::now() + chrono::Duration::days(365),
            fingerprint: format!("fp_{}", subject),
            trusted,
        }
    }

    fn make_expired_cert(subject: &str) -> CertInfo {
        CertInfo {
            subject: subject.to_string(),
            issuer: "Trusted CA".to_string(),
            serial: "002".to_string(),
            not_before: Utc::now() - chrono::Duration::days(400),
            not_after: Utc::now() - chrono::Duration::days(1),
            fingerprint: format!("fp_expired_{}", subject),
            trusted: true,
        }
    }

    #[test]
    fn test_certificate_monitor_new() {
        let monitor = CertificateMonitor::new();
        assert!(monitor.get_untrusted_certs().is_empty());
        assert!(monitor.alert_count() == 0);
    }

    #[test]
    fn test_check_certificate_valid() {
        let mut monitor = CertificateMonitor::new();
        let cert = make_cert("www.example.com", "Let's Encrypt", true);
        let alerts = monitor.check_certificate(&cert);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_check_certificate_expired() {
        let mut monitor = CertificateMonitor::new();
        let cert = make_expired_cert("old.example.com");
        let alerts = monitor.check_certificate(&cert);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.alert_type == CertAlertType::ExpiredCert));
    }

    #[test]
    fn test_check_certificate_self_signed() {
        let mut monitor = CertificateMonitor::new();
        let cert = CertInfo {
            subject: "myserver.local".to_string(),
            issuer: "myserver.local".to_string(),
            serial: "003".to_string(),
            not_before: Utc::now() - chrono::Duration::days(10),
            not_after: Utc::now() + chrono::Duration::days(365),
            fingerprint: "fp_self".to_string(),
            trusted: false,
        };
        let alerts = monitor.check_certificate(&cert);
        assert!(alerts.iter().any(|a| a.alert_type == CertAlertType::SelfSigned));
    }

    #[test]
    fn test_check_certificate_rogue_issuer() {
        let mut monitor = CertificateMonitor::new();
        let cert = CertInfo {
            subject: "evil.com".to_string(),
            issuer: "Fake CA Root".to_string(),
            serial: "004".to_string(),
            not_before: Utc::now() - chrono::Duration::days(10),
            not_after: Utc::now() + chrono::Duration::days(365),
            fingerprint: "fp_rogue".to_string(),
            trusted: false,
        };
        let alerts = monitor.check_certificate(&cert);
        assert!(alerts.iter().any(|a| a.alert_type == CertAlertType::RogueCert));
    }

    #[test]
    fn test_add_trusted_and_check() {
        let mut monitor = CertificateMonitor::new();
        monitor.add_trusted("abc123".to_string());
        assert!(monitor.trusted_certs.contains_key("abc123"));
    }

    #[test]
    fn test_check_pinning_valid() {
        let mut monitor = CertificateMonitor::new();
        assert!(monitor.check_pinning("example.com", "fp_valid"));
        assert!(monitor.check_pinning("example.com", "fp_valid"));
        assert!(monitor.alert_count() == 0);
    }

    #[test]
    fn test_check_pinning_violation() {
        let mut monitor = CertificateMonitor::new();
        monitor.check_pinning("example.com", "fp_expected");
        let result = monitor.check_pinning("example.com", "fp_wrong");
        assert!(!result);
        assert!(monitor.alert_count() > 0);
        assert!(monitor.get_alerts().iter().any(|a| a.alert_type == CertAlertType::PinningViolation));
    }

    #[test]
    fn test_detect_mitm() {
        let mut monitor = CertificateMonitor::new();
        let is_mitm = monitor.detect_mitm_indicator("example.com", "expected_fp", "observed_fp");
        assert!(is_mitm);
        assert!(monitor.alert_count() == 1);
    }

    #[test]
    fn test_no_mitm_same_fingerprint() {
        let mut monitor = CertificateMonitor::new();
        let is_mitm = monitor.detect_mitm_indicator("example.com", "same_fp", "same_fp");
        assert!(!is_mitm);
        assert!(monitor.alert_count() == 0);
    }

    #[test]
    fn test_untrusted_cert_tracked() {
        let mut monitor = CertificateMonitor::new();
        let cert = make_cert("untrusted.com", "Unknown CA", false);
        monitor.check_certificate(&cert);
        assert_eq!(monitor.get_untrusted_certs().len(), 1);
    }

    #[test]
    fn test_multiple_alerts_accumulate() {
        let mut monitor = CertificateMonitor::new();
        let cert1 = make_expired_cert("expired1.com");
        let cert2 = make_expired_cert("expired2.com");
        monitor.check_certificate(&cert1);
        monitor.check_certificate(&cert2);
        assert!(monitor.alert_count() >= 2);
    }
}
