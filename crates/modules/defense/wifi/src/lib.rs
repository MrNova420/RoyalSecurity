pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiThreatType {
    RogueAp,
    EvilTwin,
    DeauthAttack,
    UnauthorizedNetwork,
    WpsAttack,
    KarmaAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub security: String,
    pub signal_strength: i32,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiAlert {
    pub threat_type: WifiThreatType,
    pub network: WifiNetwork,
    pub message: String,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}

pub struct WifiGuard {
    trusted_networks: HashSet<String>,
    known_bssids: std::collections::HashMap<String, String>,
    detection_count: u64,
}

impl WifiGuard {
    pub fn new() -> Self {
        info!("Initializing WiFi Guard");
        Self {
            trusted_networks: HashSet::new(),
            known_bssids: std::collections::HashMap::new(),
            detection_count: 0,
        }
    }

    pub fn check_network(&mut self, network: &WifiNetwork) -> Vec<WifiAlert> {
        let mut alerts = Vec::new();

        if network.security.to_lowercase() == "none" || network.security.to_lowercase() == "open" {
            let alert = WifiAlert {
                threat_type: WifiThreatType::UnauthorizedNetwork,
                network: network.clone(),
                message: format!(
                    "Unsecured WiFi network detected: {} ({})",
                    network.ssid, network.bssid
                ),
                severity: EventSeverity::Medium,
                confidence: 0.8,
                timestamp: Utc::now(),
            };
            warn!(ssid = %network.ssid, "Unsecured WiFi network");
            self.detection_count += 1;
            alerts.push(alert);
        }

        if network.ssid.is_empty() && network.connected {
            let alert = WifiAlert {
                threat_type: WifiThreatType::KarmaAttack,
                network: network.clone(),
                message: "Connected to hidden SSID network - possible Karma attack".to_string(),
                severity: EventSeverity::High,
                confidence: 0.6,
                timestamp: Utc::now(),
            };
            self.detection_count += 1;
            alerts.push(alert);
        }

        if let Some(known_ssid) = self.known_bssids.get(&network.bssid) {
            if known_ssid != &network.ssid {
                let alert = WifiAlert {
                    threat_type: WifiThreatType::EvilTwin,
                    network: network.clone(),
                    message: format!(
                        "BSSID {} previously associated with SSID '{}', now broadcasting '{}'",
                        network.bssid, known_ssid, network.ssid
                    ),
                    severity: EventSeverity::Critical,
                    confidence: 0.95,
                    timestamp: Utc::now(),
                };
                warn!(
                    bssid = %network.bssid,
                    old_ssid = %known_ssid,
                    new_ssid = %network.ssid,
                    "Evil twin detected"
                );
                self.detection_count += 1;
                alerts.push(alert);
            }
        }

        alerts
    }

    pub fn detect_rogue_ap(&mut self, networks: &[WifiNetwork]) -> Vec<WifiAlert> {
        let mut alerts = Vec::new();

        let connected: Vec<&WifiNetwork> = networks.iter().filter(|n| n.connected).collect();
        let unconnected: Vec<&WifiNetwork> = networks.iter().filter(|n| !n.connected).collect();

        for unconn in &unconnected {
            for conn in &connected {
                if unconn.ssid == conn.ssid && unconn.bssid != conn.bssid {
                    let alert = WifiAlert {
                        threat_type: WifiThreatType::RogueAp,
                        network: (*unconn).clone(),
                        message: format!(
                            "Rogue AP detected: {} on BSSID {} (legitimate: {})",
                            unconn.ssid, unconn.bssid, conn.bssid
                        ),
                        severity: EventSeverity::Critical,
                        confidence: 0.9,
                        timestamp: Utc::now(),
                    };
                    warn!(
                        ssid = %unconn.ssid,
                        rogue_bssid = %unconn.bssid,
                        "Rogue access point detected"
                    );
                    self.detection_count += 1;
                    alerts.push(alert);
                }
            }
        }

        alerts
    }

    pub fn detect_evil_twin(&mut self, ssid: &str, bssids: &[String]) -> Option<WifiAlert> {
        if bssids.len() >= 2 {
            let first = &bssids[0];
            let has_different = bssids.iter().skip(1).any(|b| b != first);

            if has_different {
                let alert = WifiAlert {
                    threat_type: WifiThreatType::EvilTwin,
                    network: WifiNetwork {
                        ssid: ssid.to_string(),
                        bssid: bssids[1].clone(),
                        security: "WPA2".to_string(),
                        signal_strength: -50,
                        connected: false,
                    },
                    message: format!(
                        "Evil twin detected for SSID '{}': multiple BSSIDs ({})",
                        ssid,
                        bssids.join(", ")
                    ),
                    severity: EventSeverity::Critical,
                    confidence: 0.92,
                    timestamp: Utc::now(),
                };
                warn!(ssid = ssid, "Evil twin detected via BSSID comparison");
                self.detection_count += 1;
                return Some(alert);
            }
        }

        None
    }

    pub fn add_trusted_network(&mut self, ssid: &str) {
        info!(ssid = ssid, "Adding trusted WiFi network");
        self.trusted_networks.insert(ssid.to_string());
    }

    pub fn is_trusted(&self, ssid: &str) -> bool {
        self.trusted_networks.contains(ssid)
    }
}

impl Default for WifiGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_network(ssid: &str, bssid: &str, security: &str, connected: bool) -> WifiNetwork {
        WifiNetwork {
            ssid: ssid.to_string(),
            bssid: bssid.to_string(),
            security: security.to_string(),
            signal_strength: -50,
            connected,
        }
    }

    #[test]
    fn test_wifi_guard_new() {
        let guard = WifiGuard::new();
        assert_eq!(guard.detection_count, 0);
    }

    #[test]
    fn test_check_network_unsecured() {
        let mut guard = WifiGuard::new();
        let network = make_network("FreeWifi", "AA:BB:CC:DD:EE:FF", "none", false);
        let alerts = guard.check_network(&network);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].threat_type, WifiThreatType::UnauthorizedNetwork);
        assert_eq!(alerts[0].severity, EventSeverity::Medium);
    }

    #[test]
    fn test_check_network_secure_no_alert() {
        let mut guard = WifiGuard::new();
        let network = make_network("HomeWifi", "AA:BB:CC:DD:EE:FF", "WPA2", true);
        let alerts = guard.check_network(&network);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_detect_evil_twin() {
        let mut guard = WifiGuard::new();
        let bssids = vec![
            "AA:BB:CC:DD:EE:01".to_string(),
            "AA:BB:CC:DD:EE:02".to_string(),
        ];
        let alert = guard.detect_evil_twin("CoffeeShop", &bssids);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.threat_type, WifiThreatType::EvilTwin);
        assert_eq!(alert.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_no_evil_twin_single_bssid() {
        let mut guard = WifiGuard::new();
        let bssids = vec!["AA:BB:CC:DD:EE:01".to_string()];
        let alert = guard.detect_evil_twin("CoffeeShop", &bssids);
        assert!(alert.is_none());
    }

    #[test]
    fn test_no_evil_twin_same_bssid() {
        let mut guard = WifiGuard::new();
        let bssids = vec![
            "AA:BB:CC:DD:EE:01".to_string(),
            "AA:BB:CC:DD:EE:01".to_string(),
        ];
        let alert = guard.detect_evil_twin("CoffeeShop", &bssids);
        assert!(alert.is_none());
    }

    #[test]
    fn test_add_and_check_trusted() {
        let mut guard = WifiGuard::new();
        assert!(!guard.is_trusted("HomeWifi"));
        guard.add_trusted_network("HomeWifi");
        assert!(guard.is_trusted("HomeWifi"));
        assert!(!guard.is_trusted("OtherWifi"));
    }

    #[test]
    fn test_detect_rogue_ap() {
        let mut guard = WifiGuard::new();
        let networks = vec![
            make_network("CorpWifi", "AA:BB:CC:DD:EE:01", "WPA2-Enterprise", true),
            make_network("CorpWifi", "AA:BB:CC:DD:EE:99", "WPA2", false),
        ];
        let alerts = guard.detect_rogue_ap(&networks);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].threat_type, WifiThreatType::RogueAp);
        assert_eq!(alerts[0].severity, EventSeverity::Critical);
    }

    #[test]
    fn test_no_rogue_ap_different_ssids() {
        let mut guard = WifiGuard::new();
        let networks = vec![
            make_network("NetworkA", "AA:BB:CC:DD:EE:01", "WPA2", true),
            make_network("NetworkB", "AA:BB:CC:DD:EE:02", "WPA2", false),
        ];
        let alerts = guard.detect_rogue_ap(&networks);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_hidden_ssid_karma() {
        let mut guard = WifiGuard::new();
        let network = WifiNetwork {
            ssid: String::new(),
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            security: "WPA2".to_string(),
            signal_strength: -30,
            connected: true,
        };
        let alerts = guard.check_network(&network);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].threat_type, WifiThreatType::KarmaAttack);
    }
}
