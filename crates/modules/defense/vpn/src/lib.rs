pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, ProcessInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnProtocol {
    WireGuard,
    OpenVpn,
    Ipsec,
    Pptp,
    Sstp,
    IKeV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConnection {
    pub protocol: VpnProtocol,
    pub server_ip: String,
    pub local_ip: String,
    pub tunnel_type: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnAlert {
    pub message: String,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}

pub struct VpnMonitor {
    active_connections: Vec<VpnConnection>,
    trusted_vpn_servers: HashSet<String>,
    always_on: bool,
    #[allow(dead_code)]
    allowed_vpn_processes: HashSet<String>,
    alert_count: u64,
}

impl VpnMonitor {
    pub fn new() -> Self {
        info!("Initializing VPN Monitor");
        let mut allowed = HashSet::new();
        allowed.insert("wireguard.exe".to_string());
        allowed.insert("wg.exe".to_string());
        allowed.insert("openvpn.exe".to_string());
        allowed.insert("vpnclient.exe".to_string());

        Self {
            active_connections: Vec::new(),
            trusted_vpn_servers: HashSet::new(),
            always_on: true,
            allowed_vpn_processes: allowed,
            alert_count: 0,
        }
    }

    pub fn check_connection(&mut self, conn: &VpnConnection) -> Vec<VpnAlert> {
        let mut alerts = Vec::new();

        if conn.active {
            self.active_connections.push(conn.clone());
        }

        if !self.trusted_vpn_servers.is_empty()
            && !self.trusted_vpn_servers.contains(&conn.server_ip)
        {
            let alert = VpnAlert {
                message: format!(
                    "Untrusted VPN server: {} (protocol: {:?})",
                    conn.server_ip, conn.protocol
                ),
                severity: EventSeverity::Medium,
                confidence: 0.7,
                timestamp: Utc::now(),
            };
            warn!(server = %conn.server_ip, "Untrusted VPN server detected");
            self.alert_count += 1;
            alerts.push(alert);
        }

        match conn.protocol {
            VpnProtocol::Pptp => {
                let alert = VpnAlert {
                    message: "PPTP protocol detected - known to be insecure".to_string(),
                    severity: EventSeverity::High,
                    confidence: 0.95,
                    timestamp: Utc::now(),
                };
                warn!("Insecure PPTP VPN protocol detected");
                self.alert_count += 1;
                alerts.push(alert);
            }
            VpnProtocol::Ipsec if conn.tunnel_type == "transport" => {
                let alert = VpnAlert {
                    message: "IPsec transport mode - not a VPN tunnel".to_string(),
                    severity: EventSeverity::Low,
                    confidence: 0.5,
                    timestamp: Utc::now(),
                };
                self.alert_count += 1;
                alerts.push(alert);
            }
            _ => {}
        }

        alerts
    }

    pub fn enforce_always_on(&self) -> bool {
        self.always_on
    }

    pub fn detect_split_tunnel(
        &mut self,
        process: &ProcessInfo,
        routes: &[String],
    ) -> Option<VpnAlert> {
        let has_vpn_route = routes.iter().any(|r| r.contains("10.0.0.0/8") || r.contains("172.16.0.0/12"));
        let has_direct_route = routes.iter().any(|r| r == "0.0.0.0/0" || r == "default");

        if has_vpn_route && has_direct_route && self.active_connections.iter().any(|c| c.active) {
            let alert = VpnAlert {
                message: format!(
                    "Split tunneling detected for process: {} (pid: {})",
                    process.name, process.pid
                ),
                severity: EventSeverity::High,
                confidence: 0.85,
                timestamp: Utc::now(),
            };
            warn!(process = %process.name, pid = process.pid, "Split tunneling detected");
            self.alert_count += 1;
            Some(alert)
        } else {
            None
        }
    }

    pub fn get_active_vpn(&self) -> Option<VpnConnection> {
        self.active_connections.iter().find(|c| c.active).cloned()
    }

    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }
}

impl Default for VpnMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::ProcessInfo;


    fn make_vpn_connection(protocol: VpnProtocol, active: bool) -> VpnConnection {
        VpnConnection {
            protocol,
            server_ip: "10.0.0.1".to_string(),
            local_ip: "192.168.1.100".to_string(),
            tunnel_type: "tunnel".to_string(),
            active,
        }
    }

    fn make_process(name: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: name.to_string(),
            path: format!("C:\\{}", name),
            command_line: String::new(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_vpn_monitor_new() {
        let monitor = VpnMonitor::new();
        assert_eq!(monitor.alert_count(), 0);
        assert!(monitor.enforce_always_on());
    }

    #[test]
    fn test_check_connection_secure_no_alert() {
        let mut monitor = VpnMonitor::new();
        let conn = make_vpn_connection(VpnProtocol::WireGuard, true);
        let alerts = monitor.check_connection(&conn);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_check_connection_pptp_insecure() {
        let mut monitor = VpnMonitor::new();
        let conn = make_vpn_connection(VpnProtocol::Pptp, true);
        let alerts = monitor.check_connection(&conn);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, EventSeverity::High);
        assert_eq!(monitor.alert_count(), 1);
    }

    #[test]
    fn test_get_active_vpn() {
        let mut monitor = VpnMonitor::new();
        assert!(monitor.get_active_vpn().is_none());

        let conn = make_vpn_connection(VpnProtocol::WireGuard, true);
        monitor.check_connection(&conn);
        let active = monitor.get_active_vpn();
        assert!(active.is_some());
        assert_eq!(active.unwrap().protocol, VpnProtocol::WireGuard);
    }

    #[test]
    fn test_detect_split_tunnel() {
        let mut monitor = VpnMonitor::new();
        let conn = make_vpn_connection(VpnProtocol::WireGuard, true);
        monitor.check_connection(&conn);

        let process = make_process("chrome.exe");
        let routes = vec!["10.0.0.0/8".to_string(), "0.0.0.0/0".to_string()];
        let alert = monitor.detect_split_tunnel(&process, &routes);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, EventSeverity::High);
        assert_eq!(monitor.alert_count(), 1);
    }

    #[test]
    fn test_no_split_tunnel_without_vpn() {
        let mut monitor = VpnMonitor::new();
        let process = make_process("chrome.exe");
        let routes = vec!["10.0.0.0/8".to_string(), "0.0.0.0/0".to_string()];
        let alert = monitor.detect_split_tunnel(&process, &routes);
        assert!(alert.is_none());
    }

    #[test]
    fn test_check_connection_untrusted_server() {
        let mut monitor = VpnMonitor::new();
        monitor.trusted_vpn_servers.insert("1.1.1.1".to_string());
        let conn = VpnConnection {
            protocol: VpnProtocol::OpenVpn,
            server_ip: "99.99.99.99".to_string(),
            local_ip: "192.168.1.100".to_string(),
            tunnel_type: "tunnel".to_string(),
            active: true,
        };
        let alerts = monitor.check_connection(&conn);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.message.contains("Untrusted")));
    }

    #[test]
    fn test_inactive_connection_not_in_active() {
        let mut monitor = VpnMonitor::new();
        let conn = make_vpn_connection(VpnProtocol::WireGuard, false);
        monitor.check_connection(&conn);
        assert!(monitor.get_active_vpn().is_none());
    }
}
