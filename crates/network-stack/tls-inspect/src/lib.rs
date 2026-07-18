pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, NetworkEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TlsInspectError {
    #[error("invalid certificate chain: {0}")]
    InvalidChain(String),
    #[error("handshake parse failure: {0}")]
    HandshakeParseFailure(String),
}

// ---------------------------------------------------------------------------
// TlsAlertType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsAlertType {
    SelfSigned,
    Expired,
    Revoked,
    PinningViolation,
    WeakCipher,
    UnknownCa,
    SniMismatch,
}

// ---------------------------------------------------------------------------
// TlsVersion
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Ssl30,
}

// ---------------------------------------------------------------------------
// CertChainInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san: Vec<String>,
    pub fingerprint: String,
}

// ---------------------------------------------------------------------------
// TlsHandshake
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshake {
    pub ja3_hash: String,
    pub ja4_hash: String,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cert_chain: Vec<CertChainInfo>,
    pub version: TlsVersion,
    pub cipher_suite: u16,
}

// ---------------------------------------------------------------------------
// TlsAlert
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAlert {
    pub alert_type: TlsAlertType,
    pub message: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// TlsInspector
// ---------------------------------------------------------------------------

pub struct TlsInspector {
    known_weak_ciphers: Vec<u16>,
    alert_count: u64,
    pinned_domains: HashMap<String, String>,
}

impl TlsInspector {
    pub fn new() -> Self {
        info!("Initialized TLS inspector");
        Self {
            known_weak_ciphers: vec![
                0x0005, // TLS_RSA_WITH_RC4_128_SHA
                0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
                0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
                0xc004, // TLS_ECDH_RSA_WITH_RC4_128_SHA
                0xc012, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
            ],
            alert_count: 0,
            pinned_domains: HashMap::new(),
        }
    }

    pub fn inspect_handshake(&mut self, handshake: &TlsHandshake) -> Vec<TlsAlert> {
        let mut alerts = Vec::new();

        for cert in &handshake.cert_chain {
            if cert.issuer == cert.subject {
                alerts.push(TlsAlert {
                    alert_type: TlsAlertType::SelfSigned,
                    message: format!("Self-signed certificate: {}", cert.subject),
                    severity: EventSeverity::High,
                    timestamp: Utc::now(),
                });
            }

            if Utc::now() > cert.not_after {
                alerts.push(TlsAlert {
                    alert_type: TlsAlertType::Expired,
                    message: format!(
                        "Expired certificate: {} (expired {})",
                        cert.subject, cert.not_after
                    ),
                    severity: EventSeverity::High,
                    timestamp: Utc::now(),
                });
            }

            if Utc::now() < cert.not_before {
                alerts.push(TlsAlert {
                    alert_type: TlsAlertType::Expired,
                    message: format!(
                        "Not yet valid certificate: {} (valid from {})",
                        cert.subject, cert.not_before
                    ),
                    severity: EventSeverity::Medium,
                    timestamp: Utc::now(),
                });
            }
        }

        if self.is_weak_cipher(handshake.cipher_suite) {
            alerts.push(TlsAlert {
                alert_type: TlsAlertType::WeakCipher,
                message: format!("Weak cipher suite: 0x{:04x}", handshake.cipher_suite),
                severity: EventSeverity::Medium,
                timestamp: Utc::now(),
            });
        }

        if let Some(ref sni) = handshake.sni {
            if let Some(expected) = self.pinned_domains.get(sni) {
                if let Some(cert) = handshake.cert_chain.first() {
                    if !cert.san.iter().any(|s| s == expected) {
                        alerts.push(TlsAlert {
                            alert_type: TlsAlertType::PinningViolation,
                            message: format!(
                                "Certificate pinning violation for {sni}: expected {expected}"
                            ),
                            severity: EventSeverity::Critical,
                            timestamp: Utc::now(),
                        });
                    }
                }
            }
        }

        if matches!(handshake.version, TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11) {
            alerts.push(TlsAlert {
                alert_type: TlsAlertType::WeakCipher,
                message: format!("Deprecated TLS version: {:?}", handshake.version),
                severity: EventSeverity::High,
                timestamp: Utc::now(),
            });
        }

        self.alert_count += alerts.len() as u64;
        debug!(alerts_generated = alerts.len(), "TLS inspection complete");
        alerts
    }

    pub fn validate_cert_chain(&mut self, chain: &[CertChainInfo]) -> Vec<TlsAlert> {
        let mut alerts = Vec::new();

        if chain.is_empty() {
            alerts.push(TlsAlert {
                alert_type: TlsAlertType::UnknownCa,
                message: "Empty certificate chain".to_string(),
                severity: EventSeverity::High,
                timestamp: Utc::now(),
            });
            self.alert_count += 1;
            return alerts;
        }

        for (i, cert) in chain.iter().enumerate() {
            if cert.issuer == cert.subject && i > 0 {
                alerts.push(TlsAlert {
                    alert_type: TlsAlertType::SelfSigned,
                    message: format!("Intermediate certificate is self-signed: {}", cert.subject),
                    severity: EventSeverity::High,
                    timestamp: Utc::now(),
                });
            }

            if Utc::now() > cert.not_after {
                alerts.push(TlsAlert {
                    alert_type: TlsAlertType::Expired,
                    message: format!("Certificate expired: {}", cert.subject),
                    severity: EventSeverity::High,
                    timestamp: Utc::now(),
                });
            }
        }

        if chain.len() > 1 {
            for i in 0..chain.len() - 1 {
                let child = &chain[i];
                let parent = &chain[i + 1];
                if child.issuer != parent.subject {
                    alerts.push(TlsAlert {
                        alert_type: TlsAlertType::UnknownCa,
                        message: format!(
                            "Chain break: {} issued by {}, but next cert is {}",
                            child.subject, child.issuer, parent.subject
                        ),
                        severity: EventSeverity::Critical,
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        self.alert_count += alerts.len() as u64;
        alerts
    }

    pub fn calculate_ja4(&self, handshake: &TlsHandshake) -> String {
        let version = match handshake.version {
            TlsVersion::Tls13 => "13",
            TlsVersion::Tls12 => "12",
            TlsVersion::Tls11 => "11",
            TlsVersion::Tls10 => "10",
            TlsVersion::Ssl30 => "30",
        };
        let cipher_count = format!("{:02}", 1);
        let ext_count = format!("{:02}", handshake.alpn.len());
        let alpn_first = handshake.alpn.first().map(|a| &a[..2]).unwrap_or("00");

        format!(
            "t{version}_{cipher_count}{ext_count}_{alpn_first}_h{hash}",
            hash = &handshake.ja3_hash[..handshake.ja3_hash.len().min(12)],
        )
    }

    pub fn check_sni(&self, sni: &str, expected_domain: &str) -> bool {
        let sni_lower = sni.to_lowercase();
        let expected_lower = expected_domain.to_lowercase();

        sni_lower == expected_lower
            || sni_lower.ends_with(&format!(".{expected_lower}"))
    }

    pub fn is_weak_cipher(&self, suite: u16) -> bool {
        self.known_weak_ciphers.contains(&suite)
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }

    pub fn add_pinned_domain(&mut self, domain: String, expected_fingerprint: String) {
        info!(domain = %domain, "Added certificate pin");
        self.pinned_domains.insert(domain, expected_fingerprint);
    }
}

impl Default for TlsInspector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handshake(ja3: &str, cipher: u16, sni: Option<String>) -> TlsHandshake {
        TlsHandshake {
            ja3_hash: ja3.to_string(),
            ja4_hash: String::new(),
            sni,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            cert_chain: vec![CertChainInfo {
                subject: "CN=example.com".to_string(),
                issuer: "CN=Let's Encrypt".to_string(),
                serial: "01".to_string(),
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(90),
                san: vec!["example.com".to_string()],
                fingerprint: "abc123".to_string(),
            }],
            version: TlsVersion::Tls12,
            cipher_suite: cipher,
        }
    }

    #[test]
    fn test_new_inspector() {
        let inspector = TlsInspector::new();
        assert_eq!(inspector.alert_count(), 0);
    }

    #[test]
    fn test_inspect_valid_handshake() {
        let mut inspector = TlsInspector::new();
        let handshake = make_handshake("abc123", 0x1301, Some("example.com".to_string()));
        let alerts = inspector.inspect_handshake(&handshake);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_inspect_weak_cipher() {
        let mut inspector = TlsInspector::new();
        let handshake = make_handshake("abc123", 0x0005, Some("example.com".to_string()));
        let alerts = inspector.inspect_handshake(&handshake);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, TlsAlertType::WeakCipher);
    }

    #[test]
    fn test_inspect_self_signed() {
        let mut inspector = TlsInspector::new();
        let mut handshake = make_handshake("abc123", 0x1301, None);
        handshake.cert_chain[0].subject = "CN=self-signed".to_string();
        handshake.cert_chain[0].issuer = "CN=self-signed".to_string();
        let alerts = inspector.inspect_handshake(&handshake);
        assert!(alerts.iter().any(|a| a.alert_type == TlsAlertType::SelfSigned));
    }

    #[test]
    fn test_inspect_expired_cert() {
        let mut inspector = TlsInspector::new();
        let mut handshake = make_handshake("abc123", 0x1301, None);
        handshake.cert_chain[0].not_after = Utc::now() - chrono::Duration::days(30);
        let alerts = inspector.inspect_handshake(&handshake);
        assert!(alerts.iter().any(|a| a.alert_type == TlsAlertType::Expired));
    }

    #[test]
    fn test_validate_empty_chain() {
        let mut inspector = TlsInspector::new();
        let alerts = inspector.validate_cert_chain(&[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, TlsAlertType::UnknownCa);
    }

    #[test]
    fn test_validate_chain_break() {
        let mut inspector = TlsInspector::new();
        let chain = vec![
            CertChainInfo {
                subject: "CN=leaf".to_string(),
                issuer: "CN=intermediate".to_string(),
                serial: "01".to_string(),
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(365),
                san: vec![],
                fingerprint: "a".to_string(),
            },
            CertChainInfo {
                subject: "CN=root".to_string(),
                issuer: "CN=root".to_string(),
                serial: "02".to_string(),
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(365),
                san: vec![],
                fingerprint: "b".to_string(),
            },
        ];
        let alerts = inspector.validate_cert_chain(&chain);
        assert!(alerts.iter().any(|a| a.alert_type == TlsAlertType::UnknownCa));
    }

    #[test]
    fn test_check_sni_exact() {
        let inspector = TlsInspector::new();
        assert!(inspector.check_sni("example.com", "example.com"));
    }

    #[test]
    fn test_check_sni_subdomain() {
        let inspector = TlsInspector::new();
        assert!(inspector.check_sni("sub.example.com", "example.com"));
    }

    #[test]
    fn test_check_sni_mismatch() {
        let inspector = TlsInspector::new();
        assert!(!inspector.check_sni("evil.com", "example.com"));
    }

    #[test]
    fn test_is_weak_cipher() {
        let inspector = TlsInspector::new();
        assert!(inspector.is_weak_cipher(0x0005));
        assert!(inspector.is_weak_cipher(0x000a));
        assert!(!inspector.is_weak_cipher(0x1301));
    }

    #[test]
    fn test_calculate_ja4() {
        let inspector = TlsInspector::new();
        let handshake = make_handshake("a]b]c]d]e]f]g", 0x1301, None);
        let ja4 = inspector.calculate_ja4(&handshake);
        assert!(ja4.starts_with("t12_"));
    }

    #[test]
    fn test_deprecated_tls_version() {
        let mut inspector = TlsInspector::new();
        let mut handshake = make_handshake("abc", 0x1301, None);
        handshake.version = TlsVersion::Tls10;
        let alerts = inspector.inspect_handshake(&handshake);
        assert!(alerts.iter().any(|a| a.alert_type == TlsAlertType::WeakCipher));
    }
}
