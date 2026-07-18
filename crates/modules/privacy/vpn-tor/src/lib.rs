pub mod prelude;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeakType {
    DnsLeak,
    WebRtcLeak,
    IpLeak,
    MtuLeak,
    TrafficLeak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakDetection {
    pub leak_type: LeakType,
    pub detected_at: DateTime<Utc>,
    pub process: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    pub kill_switch: bool,
    pub dns_leak_prevention: bool,
    pub webrtc_block: bool,
    pub enforce_tor: bool,
    pub leaky_vpn_threshold_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyStatus {
    pub vpn_active: bool,
    pub tor_active: bool,
    pub kill_switch_active: bool,
    pub leaks_detected: u32,
    pub blocked_connections: u32,
}

pub struct PrivacyGuard {
    config: PrivacyConfig,
    leaks: Vec<LeakDetection>,
    blocked_connections: u32,
    kill_switch_active: bool,
}

impl PrivacyGuard {
    pub fn new() -> Self {
        Self {
            config: PrivacyConfig {
                kill_switch: true,
                dns_leak_prevention: true,
                webrtc_block: true,
                enforce_tor: false,
                leaky_vpn_threshold_secs: 30,
            },
            leaks: Vec::new(),
            blocked_connections: 0,
            kill_switch_active: true,
        }
    }

    pub fn with_config(config: PrivacyConfig) -> Self {
        let kill_switch_active = config.kill_switch;
        Self {
            config,
            leaks: Vec::new(),
            blocked_connections: 0,
            kill_switch_active,
        }
    }

    pub fn check_dns_leak(&mut self, dns_server: &str, expected_dns: &str) -> Option<LeakDetection> {
        if !self.config.dns_leak_prevention {
            return None;
        }

        if dns_server != expected_dns {
            let detection = LeakDetection {
                leak_type: LeakType::DnsLeak,
                detected_at: Utc::now(),
                process: "dns_resolver".to_string(),
                details: format!(
                    "DNS leak detected: using '{}' instead of expected '{}'",
                    dns_server, expected_dns
                ),
            };

            self.leaks.push(detection.clone());
            self.blocked_connections += 1;
            Some(detection)
        } else {
            None
        }
    }

    pub fn check_webrtc_leak(&mut self, local_ip: &str, public_ip: &str) -> Option<LeakDetection> {
        if !self.config.webrtc_block {
            return None;
        }

        if local_ip != public_ip {
            let detection = LeakDetection {
                leak_type: LeakType::WebRtcLeak,
                detected_at: Utc::now(),
                process: "webrtc".to_string(),
                details: format!(
                    "WebRTC leak: local IP '{}' exposed alongside public IP '{}'",
                    local_ip, public_ip
                ),
            };

            self.leaks.push(detection.clone());
            self.blocked_connections += 1;
            Some(detection)
        } else {
            None
        }
    }

    pub fn check_ip_leak(&mut self, expected_ip: &str, actual_ip: &str) -> Option<LeakDetection> {
        if expected_ip != actual_ip {
            let detection = LeakDetection {
                leak_type: LeakType::IpLeak,
                detected_at: Utc::now(),
                process: "network".to_string(),
                details: format!(
                    "IP leak: actual IP '{}' does not match expected VPN IP '{}'",
                    actual_ip, expected_ip
                ),
            };

            self.leaks.push(detection.clone());
            self.blocked_connections += 1;
            Some(detection)
        } else {
            None
        }
    }

    pub fn get_status(&self) -> PrivacyStatus {
        PrivacyStatus {
            vpn_active: true,
            tor_active: self.config.enforce_tor,
            kill_switch_active: self.kill_switch_active,
            leaks_detected: self.leaks.len() as u32,
            blocked_connections: self.blocked_connections,
        }
    }

    pub fn activate_kill_switch(&mut self) {
        self.kill_switch_active = true;
        self.config.kill_switch = true;
    }

    pub fn deactivate_kill_switch(&mut self) {
        self.kill_switch_active = false;
        self.config.kill_switch = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_privacy_guard() {
        let guard = PrivacyGuard::new();
        let status = guard.get_status();
        assert!(status.kill_switch_active);
        assert!(!status.tor_active);
        assert_eq!(status.leaks_detected, 0);
    }

    #[test]
    fn test_with_config() {
        let config = PrivacyConfig {
            kill_switch: false,
            dns_leak_prevention: true,
            webrtc_block: true,
            enforce_tor: true,
            leaky_vpn_threshold_secs: 60,
        };
        let guard = PrivacyGuard::with_config(config);
        let status = guard.get_status();
        assert!(!status.kill_switch_active);
        assert!(status.tor_active);
    }

    #[test]
    fn test_check_dns_leak_detected() {
        let mut guard = PrivacyGuard::new();
        let leak = guard.check_dns_leak("8.8.8.8", "1.1.1.1");
        assert!(leak.is_some());
        assert_eq!(leak.unwrap().leak_type, LeakType::DnsLeak);
        assert_eq!(guard.get_status().leaks_detected, 1);
    }

    #[test]
    fn test_check_dns_leak_clean() {
        let mut guard = PrivacyGuard::new();
        let leak = guard.check_dns_leak("1.1.1.1", "1.1.1.1");
        assert!(leak.is_none());
        assert_eq!(guard.get_status().leaks_detected, 0);
    }

    #[test]
    fn test_check_webrtc_leak() {
        let mut guard = PrivacyGuard::new();
        let leak = guard.check_webrtc_leak("192.168.1.100", "203.0.113.50");
        assert!(leak.is_some());
        assert_eq!(leak.unwrap().leak_type, LeakType::WebRtcLeak);
    }

    #[test]
    fn test_check_webrtc_no_leak() {
        let mut guard = PrivacyGuard::new();
        let leak = guard.check_webrtc_leak("203.0.113.50", "203.0.113.50");
        assert!(leak.is_none());
    }

    #[test]
    fn test_check_ip_leak() {
        let mut guard = PrivacyGuard::new();
        let leak = guard.check_ip_leak("10.0.0.1", "203.0.113.50");
        assert!(leak.is_some());
        assert_eq!(leak.unwrap().leak_type, LeakType::IpLeak);
        assert_eq!(guard.get_status().blocked_connections, 1);
    }

    #[test]
    fn test_activate_deactivate_kill_switch() {
        let mut guard = PrivacyGuard::new();
        assert!(guard.get_status().kill_switch_active);

        guard.deactivate_kill_switch();
        assert!(!guard.get_status().kill_switch_active);

        guard.activate_kill_switch();
        assert!(guard.get_status().kill_switch_active);
    }

    #[test]
    fn test_dns_leak_prevention_disabled() {
        let config = PrivacyConfig {
            kill_switch: true,
            dns_leak_prevention: false,
            webrtc_block: true,
            enforce_tor: false,
            leaky_vpn_threshold_secs: 30,
        };
        let mut guard = PrivacyGuard::with_config(config);
        let leak = guard.check_dns_leak("8.8.8.8", "1.1.1.1");
        assert!(leak.is_none());
    }

    #[test]
    fn test_webrtc_block_disabled() {
        let config = PrivacyConfig {
            kill_switch: true,
            dns_leak_prevention: true,
            webrtc_block: false,
            enforce_tor: false,
            leaky_vpn_threshold_secs: 30,
        };
        let mut guard = PrivacyGuard::with_config(config);
        let leak = guard.check_webrtc_leak("192.168.1.1", "203.0.113.50");
        assert!(leak.is_none());
    }

    #[test]
    fn test_multiple_leaks_accumulate() {
        let mut guard = PrivacyGuard::new();
        guard.check_dns_leak("8.8.8.8", "1.1.1.1");
        guard.check_webrtc_leak("192.168.1.1", "203.0.113.50");
        guard.check_ip_leak("10.0.0.1", "203.0.113.50");

        let status = guard.get_status();
        assert_eq!(status.leaks_detected, 3);
        assert_eq!(status.blocked_connections, 3);
    }

    #[test]
    fn test_status_after_kill_switch_deactivate() {
        let mut guard = PrivacyGuard::new();
        guard.deactivate_kill_switch();
        let status = guard.get_status();
        assert!(!status.kill_switch_active);

        guard.activate_kill_switch();
        let status = guard.get_status();
        assert!(status.kill_switch_active);
    }
}
