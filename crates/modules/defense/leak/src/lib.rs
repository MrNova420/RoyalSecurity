pub mod prelude;

use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakSourceType {
    LogFile,
    MemoryDump,
    ConfigFile,
    EnvironmentVariable,
    Clipboard,
    HardcodedCredential,
}

impl std::fmt::Display for LeakSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeakSourceType::LogFile => write!(f, "Log File"),
            LeakSourceType::MemoryDump => write!(f, "Memory Dump"),
            LeakSourceType::ConfigFile => write!(f, "Config File"),
            LeakSourceType::EnvironmentVariable => write!(f, "Environment Variable"),
            LeakSourceType::Clipboard => write!(f, "Clipboard"),
            LeakSourceType::HardcodedCredential => write!(f, "Hardcoded Credential"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakSource {
    pub source_type: LeakSourceType,
    pub location: String,
    pub exposed_data: String,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakDetection {
    pub id: Uuid,
    pub leak_source: LeakSource,
    pub pattern_matched: String,
    pub recommendation: String,
}

pub struct LeakDetector {
    known_patterns: Vec<LeakPattern>,
    known_leaks: Vec<KnownLeak>,
    detection_count: u64,
}

#[derive(Debug, Clone)]
struct LeakPattern {
    pattern: String,
    name: String,
    severity: EventSeverity,
}

#[derive(Debug, Clone)]
struct KnownLeak {
    pattern: String,
    source: String,
}

impl LeakDetector {
    pub fn new() -> Self {
        info!("Initializing leak detector");
        let mut detector = Self {
            known_patterns: Vec::new(),
            known_leaks: Vec::new(),
            detection_count: 0,
        };
        detector.load_default_patterns();
        detector
    }

    fn load_default_patterns(&mut self) {
        self.known_patterns = vec![
            LeakPattern {
                pattern: "password".to_string(),
                name: "Password Field".to_string(),
                severity: EventSeverity::High,
            },
            LeakPattern {
                pattern: "secret".to_string(),
                name: "Secret Field".to_string(),
                severity: EventSeverity::High,
            },
            LeakPattern {
                pattern: "api_key".to_string(),
                name: "API Key".to_string(),
                severity: EventSeverity::Medium,
            },
            LeakPattern {
                pattern: "token".to_string(),
                name: "Token".to_string(),
                severity: EventSeverity::Medium,
            },
            LeakPattern {
                pattern: "private_key".to_string(),
                name: "Private Key".to_string(),
                severity: EventSeverity::Critical,
            },
            LeakPattern {
                pattern: "connection_string".to_string(),
                name: "Connection String".to_string(),
                severity: EventSeverity::High,
            },
        ];
    }

    pub fn scan_text(&mut self, text: &str, context: &str) -> Vec<LeakDetection> {
        let text_lower = text.to_lowercase();
        let mut detections = Vec::new();

        for pattern in &self.known_patterns {
            if text_lower.contains(&pattern.pattern) {
                let detection = LeakDetection {
                    id: Uuid::new_v4(),
                    leak_source: LeakSource {
                        source_type: LeakSourceType::LogFile,
                        location: context.to_string(),
                        exposed_data: text.to_string(),
                        severity: pattern.severity,
                    },
                    pattern_matched: pattern.name.clone(),
                    recommendation: format!(
                        "Found '{}' pattern in {}. Remove or encrypt sensitive data.",
                        pattern.pattern, context
                    ),
                };
                warn!(
                    pattern = %pattern.pattern,
                    context = context,
                    "Credential leak detected in text"
                );
                self.detection_count += 1;
                detections.push(detection);
            }
        }

        for known in &self.known_leaks {
            if text_lower.contains(&known.pattern.to_lowercase()) {
                let detection = LeakDetection {
                    id: Uuid::new_v4(),
                    leak_source: LeakSource {
                        source_type: LeakSourceType::HardcodedCredential,
                        location: context.to_string(),
                        exposed_data: text.to_string(),
                        severity: EventSeverity::Critical,
                    },
                    pattern_matched: format!("Known leak: {}", known.source),
                    recommendation: format!(
                        "Matched known leak pattern '{}' from {}. Rotate credentials immediately.",
                        known.pattern, known.source
                    ),
                };
                warn!(
                    pattern = %known.pattern,
                    "Known credential leak pattern matched"
                );
                self.detection_count += 1;
                detections.push(detection);
            }
        }

        detections
    }

    pub fn check_hardcoded_credential(
        &mut self,
        file_path: &str,
        content: &str,
    ) -> Option<LeakDetection> {
        let content_lower = content.to_lowercase();

        let hardcoded_patterns = [
            "password=",
            "password :",
            "api_key=",
            "apikey=",
            "secret_key=",
            "access_token=",
            "private_key=",
            "begin rsa private key",
            "begin private key",
            "connectionstring=",
            "server=.*;password=.*",
        ];

        for pat in &hardcoded_patterns {
            if content_lower.contains(pat) {
                let detection = LeakDetection {
                    id: Uuid::new_v4(),
                    leak_source: LeakSource {
                        source_type: LeakSourceType::HardcodedCredential,
                        location: file_path.to_string(),
                        exposed_data: content.to_string(),
                        severity: EventSeverity::Critical,
                    },
                    pattern_matched: pat.to_string(),
                    recommendation: format!(
                        "Hardcoded credential found in {}. Move to a secrets manager.",
                        file_path
                    ),
                };
                warn!(
                    file = file_path,
                    pattern = pat,
                    "Hardcoded credential detected"
                );
                self.detection_count += 1;
                return Some(detection);
            }
        }

        None
    }

    pub fn add_known_leak(&mut self, pattern: String, source: String) {
        info!(
            pattern = %pattern,
            source = %source,
            "Adding known leak pattern"
        );
        self.known_leaks.push(KnownLeak { pattern, source });
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }
}

impl Default for LeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leak_detector_new() {
        let detector = LeakDetector::new();
        assert_eq!(detector.detection_count(), 0);
        assert!(!detector.known_patterns.is_empty());
    }

    #[test]
    fn test_scan_text_detects_password() {
        let mut detector = LeakDetector::new();
        let detections = detector.scan_text("user password=secret123", "test.log");
        assert!(!detections.is_empty());
        assert_eq!(detections[0].pattern_matched, "Password Field");
        assert_eq!(detections[0].leak_source.severity, EventSeverity::High);
    }

    #[test]
    fn test_scan_text_detects_api_key() {
        let mut detector = LeakDetector::new();
        let detections = detector.scan_text("config: api_key=abc123", "config.txt");
        assert!(!detections.is_empty());
        let has_api = detections.iter().any(|d| d.pattern_matched == "API Key");
        assert!(has_api);
    }

    #[test]
    fn test_scan_text_clean() {
        let mut detector = LeakDetector::new();
        let detections = detector.scan_text("hello world nothing sensitive here", "readme.txt");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_scan_text_multiple_patterns() {
        let mut detector = LeakDetector::new();
        let detections =
            detector.scan_text("password=test private_key=rsa123 token=xyz", "multi.txt");
        assert!(detections.len() >= 2);
    }

    #[test]
    fn test_check_hardcoded_credential() {
        let mut detector = LeakDetector::new();
        let result = detector.check_hardcoded_credential(
            "app.config",
            "database_password=SuperSecret123",
        );
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(
            detection.leak_source.source_type,
            LeakSourceType::HardcodedCredential
        );
        assert_eq!(detection.leak_source.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_check_hardcoded_credential_rsa_key() {
        let mut detector = LeakDetector::new();
        let result = detector.check_hardcoded_credential(
            "keys.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_check_hardcoded_credential_clean() {
        let mut detector = LeakDetector::new();
        let result =
            detector.check_hardcoded_credential("readme.md", "This is just documentation.");
        assert!(result.is_none());
    }

    #[test]
    fn test_add_known_leak() {
        let mut detector = LeakDetector::new();
        detector.add_known_leak("AKIA1234567890ABCDE".to_string(), "AWS".to_string());
        let detections =
            detector.scan_text("Found key AKIA1234567890ABCDE in logs", "access.log");
        assert!(!detections.is_empty());
        assert!(detections[0]
            .pattern_matched
            .contains("Known leak"));
    }

    #[test]
    fn test_detection_count() {
        let mut detector = LeakDetector::new();
        detector.scan_text("password=test", "a.log");
        detector.scan_text("secret=test", "b.log");
        assert_eq!(detector.detection_count(), 2);
    }
}
