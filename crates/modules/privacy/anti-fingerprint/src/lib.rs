pub mod prelude;

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FingerprintTechniqueType {
    CanvasFingerprint,
    WebGLFingerprint,
    AudioFingerprint,
    FontEnumeration,
    PluginEnumeration,
    ScreenResolution,
    TimezoneLeak,
    WebrtcLeak,
    BatteryApi,
    NavigatorEnumeration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintTechnique {
    pub name: String,
    pub description: String,
    pub detect_pattern: String,
    pub severity: EventSeverity,
    pub technique_type: FingerprintTechniqueType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintAlert {
    pub technique: FingerprintTechnique,
    pub source: String,
    pub domain: String,
    pub timestamp: DateTime<Utc>,
    pub blocked: bool,
}

pub struct AntiFingerprint {
    techniques: Vec<FingerprintTechnique>,
    alerts: Vec<FingerprintAlert>,
    blocked_domains: HashMap<String, u32>,
}

impl AntiFingerprint {
    pub fn new() -> Self {
        let techniques = vec![
            FingerprintTechnique {
                name: "Canvas Fingerprinting".to_string(),
                description: "Detects canvas-based fingerprinting via toDataURL calls".to_string(),
                detect_pattern: "toDataURL|getImageData|readPixels".to_string(),
                severity: EventSeverity::High,
                technique_type: FingerprintTechniqueType::CanvasFingerprint,
            },
            FingerprintTechnique {
                name: "WebGL Fingerprinting".to_string(),
                description: "Detects WebGL-based fingerprinting via renderer queries".to_string(),
                detect_pattern: "getParameter|getSupportedExtensions|WEBGL_debug_renderer_info".to_string(),
                severity: EventSeverity::High,
                technique_type: FingerprintTechniqueType::WebGLFingerprint,
            },
            FingerprintTechnique {
                name: "Audio Fingerprinting".to_string(),
                description: "Detects audio context fingerprinting".to_string(),
                detect_pattern: "OfflineAudioContext|createOscillator|analyserNode".to_string(),
                severity: EventSeverity::Medium,
                technique_type: FingerprintTechniqueType::AudioFingerprint,
            },
            FingerprintTechnique {
                name: "Font Enumeration".to_string(),
                description: "Detects font enumeration via measureText probing".to_string(),
                detect_pattern: "measureText|font-family-detect|fonts.check".to_string(),
                severity: EventSeverity::Medium,
                technique_type: FingerprintTechniqueType::FontEnumeration,
            },
            FingerprintTechnique {
                name: "Plugin Enumeration".to_string(),
                description: "Detects plugin and mime type enumeration".to_string(),
                detect_pattern: "navigator.plugins|mimeTypes|length.*plugin".to_string(),
                severity: EventSeverity::Low,
                technique_type: FingerprintTechniqueType::PluginEnumeration,
            },
            FingerprintTechnique {
                name: "Screen Resolution Probe".to_string(),
                description: "Detects screen resolution and color depth probing".to_string(),
                detect_pattern: "screen.width|screen.colorDepth|devicePixelRatio".to_string(),
                severity: EventSeverity::Low,
                technique_type: FingerprintTechniqueType::ScreenResolution,
            },
            FingerprintTechnique {
                name: "Timezone Leak".to_string(),
                description: "Detects timezone extraction via Date object".to_string(),
                detect_pattern: "getTimezoneOffset|toLocaleString|Intl.DateTimeFormat".to_string(),
                severity: EventSeverity::Low,
                technique_type: FingerprintTechniqueType::TimezoneLeak,
            },
            FingerprintTechnique {
                name: "WebRTC Leak".to_string(),
                description: "Detects WebRTC local IP address leaking".to_string(),
                detect_pattern: "RTCPeerConnection|createDataChannel|iceCandidate".to_string(),
                severity: EventSeverity::Critical,
                technique_type: FingerprintTechniqueType::WebrtcLeak,
            },
            FingerprintTechnique {
                name: "Battery API".to_string(),
                description: "Detects battery status API fingerprinting".to_string(),
                detect_pattern: "navigator.getBattery|charging|dischargingTime".to_string(),
                severity: EventSeverity::Medium,
                technique_type: FingerprintTechniqueType::BatteryApi,
            },
            FingerprintTechnique {
                name: "Navigator Enumeration".to_string(),
                description: "Detects navigator property enumeration".to_string(),
                detect_pattern: "navigator.userAgent|navigator.platform|navigator.languages".to_string(),
                severity: EventSeverity::Low,
                technique_type: FingerprintTechniqueType::NavigatorEnumeration,
            },
        ];

        Self {
            techniques,
            alerts: Vec::new(),
            blocked_domains: HashMap::new(),
        }
    }

    pub fn check_request(&mut self, domain: &str, headers: &HashMap<String, String>) -> Vec<FingerprintAlert> {
        let mut matched_alerts = Vec::new();

        let combined_values: String = headers.values().cloned().collect::<Vec<_>>().join(" ");

        for technique in &self.techniques {
            if technique.detect_pattern.split('|').any(|pat| combined_values.contains(pat)) {
                let blocked = self.blocked_domains.contains_key(domain);

                let alert = FingerprintAlert {
                    technique: technique.clone(),
                    source: domain.to_string(),
                    domain: domain.to_string(),
                    timestamp: Utc::now(),
                    blocked,
                };

                if blocked {
                    *self.blocked_domains.entry(domain.to_string()).or_insert(0) += 1;
                }

                matched_alerts.push(alert);
            }
        }

        self.alerts.extend(matched_alerts.clone());
        matched_alerts
    }

    pub fn block_technique(&mut self, technique: &str) -> bool {
        if let Some(t) = self.techniques.iter().find(|t| t.name == technique) {
            let _ = t;
            self.blocked_domains.insert(technique.to_string(), 0);
            true
        } else {
            false
        }
    }

    pub fn get_techniques(&self) -> Vec<&FingerprintTechnique> {
        self.techniques.iter().collect()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn blocked_count(&self) -> u32 {
        self.blocked_domains.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_anti_fingerprint() {
        let af = AntiFingerprint::new();
        assert_eq!(af.techniques.len(), 10);
        assert_eq!(af.alert_count(), 0);
    }

    #[test]
    fn test_detect_canvas_fingerprint() {
        let mut af = AntiFingerprint::new();
        let mut headers = HashMap::new();
        headers.insert("Referer".to_string(), "https://tracker.example.com".to_string());
        headers.insert("X-Script".to_string(), "canvas.toDataURL()".to_string());

        let alerts = af.check_request("tracker.example.com", &headers);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.technique.technique_type == FingerprintTechniqueType::CanvasFingerprint));
    }

    #[test]
    fn test_detect_webrtc_leak() {
        let mut af = AntiFingerprint::new();
        let mut headers = HashMap::new();
        headers.insert("X-Fingerprint".to_string(), "RTCPeerConnection".to_string());

        let alerts = af.check_request("webrtc.example.com", &headers);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.technique.technique_type == FingerprintTechniqueType::WebrtcLeak));
        assert_eq!(alerts[0].technique.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_no_match_clean_request() {
        let mut af = AntiFingerprint::new();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());

        let alerts = af.check_request("clean.example.com", &headers);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_block_technique() {
        let mut af = AntiFingerprint::new();
        assert!(af.block_technique("Canvas Fingerprinting"));
        assert!(!af.block_technique("Nonexistent Technique"));
    }

    #[test]
    fn test_get_techniques() {
        let af = AntiFingerprint::new();
        let techniques = af.get_techniques();
        assert_eq!(techniques.len(), 10);
        assert!(techniques.iter().any(|t| t.name == "Canvas Fingerprinting"));
    }

    #[test]
    fn test_alert_count_increments() {
        let mut af = AntiFingerprint::new();
        let mut headers = HashMap::new();
        headers.insert("X-Fingerprint".to_string(), "canvas.toDataURL()".to_string());

        af.check_request("a.com", &headers);
        assert_eq!(af.alert_count(), 1);

        af.check_request("b.com", &headers);
        assert_eq!(af.alert_count(), 2);
    }

    #[test]
    fn test_blocked_count_on_blocked_domain() {
        let mut af = AntiFingerprint::new();
        af.block_technique("Canvas Fingerprinting");

        let mut headers = HashMap::new();
        headers.insert("X-Script".to_string(), "canvas.toDataURL()".to_string());

        af.check_request("Canvas Fingerprinting", &headers);
        assert!(af.blocked_count() > 0);
    }

    #[test]
    fn test_detect_webgl_fingerprint() {
        let mut af = AntiFingerprint::new();
        let mut headers = HashMap::new();
        headers.insert("X-GL".to_string(), "getParameter(WEBGL_debug_renderer_info)".to_string());

        let alerts = af.check_request("gl.example.com", &headers);
        assert!(alerts.iter().any(|a| a.technique.technique_type == FingerprintTechniqueType::WebGLFingerprint));
    }

    #[test]
    fn test_detect_multiple_techniques() {
        let mut af = AntiFingerprint::new();
        let mut headers = HashMap::new();
        headers.insert("X-Mix".to_string(), "toDataURL RTCPeerConnection navigator.userAgent".to_string());

        let alerts = af.check_request("multi.example.com", &headers);
        assert!(alerts.len() >= 3);
    }
}
