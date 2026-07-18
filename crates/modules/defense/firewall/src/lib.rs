pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{NetworkEvent, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    Block,
    Log,
    RateLimit,
}

impl Default for FirewallAction {
    fn default() -> Self {
        FirewallAction::Allow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

impl Default for TrafficDirection {
    fn default() -> Self {
        TrafficDirection::Both
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAddress {
    pub ip: Option<IpAddr>,
    pub subnet: Option<String>,
    pub any: bool,
}

impl Default for FirewallAddress {
    fn default() -> Self {
        Self { ip: None, subnet: None, any: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPort {
    pub port: Option<u16>,
    pub range: Option<(u16, u16)>,
    pub any: bool,
}

impl Default for FirewallPort {
    fn default() -> Self {
        Self { port: None, range: None, any: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub priority: u32,
    pub action: FirewallAction,
    pub enabled: bool,
    pub source: Option<FirewallAddress>,
    pub destination: Option<FirewallAddress>,
    pub protocol: Option<Protocol>,
    pub port: Option<FirewallPort>,
    pub process_name: Option<String>,
    pub direction: TrafficDirection,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub default_action: FirewallAction,
    pub enable_logging: bool,
    pub max_connections: u64,
    pub rate_limit_window_secs: u64,
    pub rate_limit_threshold: u32,
    pub enable_auto_block: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            default_action: FirewallAction::Allow,
            enable_logging: true,
            max_connections: 10_000,
            rate_limit_window_secs: 60,
            rate_limit_threshold: 100,
            enable_auto_block: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub action: FirewallAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallVerdict {
    pub action: FirewallAction,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub matched: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    pub rule_id: String,
    pub hits: u64,
    pub last_hit: Option<DateTime<Utc>>,
    pub blocked: u64,
    pub allowed: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimitTracker {
    pub source_ip: IpAddr,
    pub connection_times: Vec<DateTime<Utc>>,
    pub blocked_until: Option<DateTime<Utc>>,
}

pub struct HostFirewall {
    pub rules: Vec<FirewallRule>,
    pub connections: HashMap<String, ConnectionState>,
    pub rule_stats: HashMap<String, RuleStats>,
    pub config: FirewallConfig,
    pub blocked_count: u64,
    pub allowed_count: u64,
    rate_trackers: HashMap<IpAddr, RateLimitTracker>,
}

impl HostFirewall {
    pub fn new() -> Self {
        Self::with_config(FirewallConfig::default())
    }

    pub fn with_config(config: FirewallConfig) -> Self {
        let mut fw = Self {
            rules: Vec::new(),
            connections: HashMap::new(),
            rule_stats: HashMap::new(),
            config,
            blocked_count: 0,
            allowed_count: 0,
            rate_trackers: HashMap::new(),
        };
        fw.load_default_rules();
        fw
    }

    fn load_default_rules(&mut self) {
        let defaults = vec![
            FirewallRule {
                id: "FW-001".to_string(),
                name: "Block Inbound SMB".to_string(),
                priority: 10,
                action: FirewallAction::Block,
                enabled: true,
                source: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                destination: None,
                protocol: Some(Protocol::Tcp),
                port: Some(FirewallPort { port: None, range: Some((139, 445)), any: false }),
                process_name: None,
                direction: TrafficDirection::Inbound,
                description: "Block inbound SMB ports from external sources".to_string(),
            },
            FirewallRule {
                id: "FW-002".to_string(),
                name: "Block Inbound RDP".to_string(),
                priority: 20,
                action: FirewallAction::Block,
                enabled: true,
                source: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                destination: None,
                protocol: Some(Protocol::Tcp),
                port: Some(FirewallPort { port: Some(3389), range: None, any: false }),
                process_name: None,
                direction: TrafficDirection::Inbound,
                description: "Block inbound RDP connections from external sources".to_string(),
            },
            FirewallRule {
                id: "FW-003".to_string(),
                name: "Block Malicious Outbound Ports".to_string(),
                priority: 5,
                action: FirewallAction::Block,
                enabled: true,
                source: None,
                destination: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                protocol: Some(Protocol::Tcp),
                port: Some(FirewallPort { port: None, range: Some((4444, 5555)), any: false }),
                process_name: None,
                direction: TrafficDirection::Outbound,
                description: "Block outbound connections to known malicious ports".to_string(),
            },
            FirewallRule {
                id: "FW-003b".to_string(),
                name: "Block Malicious Outbound Port 1234".to_string(),
                priority: 5,
                action: FirewallAction::Block,
                enabled: true,
                source: None,
                destination: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                protocol: Some(Protocol::Tcp),
                port: Some(FirewallPort { port: Some(1234), range: None, any: false }),
                process_name: None,
                direction: TrafficDirection::Outbound,
                description: "Block outbound connection to known malicious port 1234".to_string(),
            },
            FirewallRule {
                id: "FW-004".to_string(),
                name: "Block Inbound WinRM".to_string(),
                priority: 20,
                action: FirewallAction::Block,
                enabled: true,
                source: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                destination: None,
                protocol: Some(Protocol::Tcp),
                port: Some(FirewallPort { port: None, range: Some((5985, 5986)), any: false }),
                process_name: None,
                direction: TrafficDirection::Inbound,
                description: "Block inbound WinRM connections from external sources".to_string(),
            },
            FirewallRule {
                id: "FW-005".to_string(),
                name: "Log DNS Outbound".to_string(),
                priority: 100,
                action: FirewallAction::Log,
                enabled: true,
                source: None,
                destination: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                protocol: Some(Protocol::Udp),
                port: Some(FirewallPort { port: Some(53), range: None, any: false }),
                process_name: None,
                direction: TrafficDirection::Outbound,
                description: "Log all outbound DNS queries".to_string(),
            },
            FirewallRule {
                id: "FW-006".to_string(),
                name: "Allow Loopback".to_string(),
                priority: 1,
                action: FirewallAction::Allow,
                enabled: true,
                source: Some(FirewallAddress {
                    ip: None,
                    subnet: Some("127.0.0.0/8".to_string()),
                    any: false,
                }),
                destination: None,
                protocol: None,
                port: None,
                process_name: None,
                direction: TrafficDirection::Both,
                description: "Allow all loopback traffic".to_string(),
            },
            FirewallRule {
                id: "FW-007".to_string(),
                name: "Rate Limit Inbound SSH".to_string(),
                priority: 50,
                action: FirewallAction::RateLimit,
                enabled: true,
                source: Some(FirewallAddress { ip: None, subnet: None, any: true }),
                destination: None,
                protocol: Some(Protocol::Tcp),
                port: Some(FirewallPort { port: Some(22), range: None, any: false }),
                process_name: None,
                direction: TrafficDirection::Inbound,
                description: "Rate limit inbound SSH connections".to_string(),
            },
        ];

        for rule in defaults {
            self.rule_stats.insert(
                rule.id.clone(),
                RuleStats {
                    rule_id: rule.id.clone(),
                    hits: 0,
                    last_hit: None,
                    blocked: 0,
                    allowed: 0,
                },
            );
            self.rules.push(rule);
        }

        self.rules.sort_by_key(|r| r.priority);
        tracing::info!(rules_count = self.rules.len(), "Loaded default firewall rules");
    }

    pub fn evaluate_connection(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        _src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        direction: TrafficDirection,
        process_name: Option<&str>,
    ) -> FirewallVerdict {
        if HostFirewall::is_loopback(src_ip) && HostFirewall::is_loopback(dst_ip) {
            self.allowed_count += 1;
            return FirewallVerdict {
                action: FirewallAction::Allow,
                rule_id: Some("FW-006".to_string()),
                rule_name: Some("Allow Loopback".to_string()),
                matched: true,
                reason: "Loopback traffic allowed".to_string(),
            };
        }

        let rules_snapshot: Vec<FirewallRule> = self.rules.clone();
        for rule in &rules_snapshot {
            if !rule.enabled {
                continue;
            }

            let dir_match = matches!(
                (&rule.direction, &direction),
                (TrafficDirection::Both, _)
                    | (TrafficDirection::Inbound, TrafficDirection::Inbound)
                    | (TrafficDirection::Outbound, TrafficDirection::Outbound)
            );
            if !dir_match {
                continue;
            }

            if let Some(ref rule_proto) = rule.protocol {
                if *rule_proto != Protocol::Any && *rule_proto != protocol {
                    continue;
                }
            }

            let src_match = match &rule.source {
                Some(addr) => self.ip_matches(src_ip, addr),
                None => true,
            };
            if !src_match {
                continue;
            }

            let dst_match = match &rule.destination {
                Some(addr) => self.ip_matches(dst_ip, addr),
                None => true,
            };
            if !dst_match {
                continue;
            }

            let port_match = match &rule.port {
                Some(p) => self.port_matches(dst_port, p),
                None => true,
            };
            if !port_match {
                continue;
            }

            if let Some(ref rule_process) = rule.process_name {
                match process_name {
                    Some(p) if p == rule_process.as_str() => {}
                    _ => continue,
                }
            }

            let action = if rule.action == FirewallAction::RateLimit {
                self.check_rate_limit(src_ip)
            } else {
                rule.action
            };

            let is_block = action == FirewallAction::Block;
            if is_block {
                self.blocked_count += 1;
            } else {
                self.allowed_count += 1;
            }

            if let Some(stats) = self.rule_stats.get_mut(&rule.id) {
                stats.hits += 1;
                stats.last_hit = Some(Utc::now());
                if is_block {
                    stats.blocked += 1;
                } else {
                    stats.allowed += 1;
                }
            }

            let reason = format!("Matched rule {}: {}", rule.id, rule.name);
            tracing::debug!(
                rule_id = %rule.id,
                action = ?action,
                src = %src_ip,
                dst = %dst_ip,
                "Connection evaluated against rule"
            );

            return FirewallVerdict {
                action,
                rule_id: Some(rule.id.clone()),
                rule_name: Some(rule.name.clone()),
                matched: true,
                reason,
            };
        }

        let default = self.config.default_action;
        if default == FirewallAction::Block {
            self.blocked_count += 1;
        } else {
            self.allowed_count += 1;
        }

        tracing::debug!(
            src = %src_ip,
            dst = %dst_ip,
            action = ?default,
            "No rule matched, applying default action"
        );

        FirewallVerdict {
            action: default,
            rule_id: None,
            rule_name: None,
            matched: false,
            reason: format!("No rule matched, default action: {:?}", default),
        }
    }

    pub fn evaluate_network_event(&mut self, event: &NetworkEvent) -> FirewallVerdict {
        let src_ip = event.src_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let dst_ip = event.dst_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let direction = TrafficDirection::Outbound;

        self.evaluate_connection(
            src_ip,
            dst_ip,
            event.src_port,
            event.dst_port,
            event.protocol,
            direction,
            event.process_name.as_deref(),
        )
    }

    pub fn is_loopback(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4 == std::net::Ipv4Addr::UNSPECIFIED,
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    pub fn is_external_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                if v4.is_loopback() {
                    return false;
                }
                if octets[0] == 10 {
                    return false;
                }
                if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                    return false;
                }
                if octets[0] == 192 && octets[1] == 168 {
                    return false;
                }
                if octets[0] == 169 && octets[1] == 254 {
                    return false;
                }
                true
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return false;
                }
                let segments = v6.segments();
                if segments[0] == 0xfe80 {
                    return false;
                }
                true
            }
        }
    }

    pub fn ip_matches(&self, ip: IpAddr, rule_addr: &FirewallAddress) -> bool {
        if rule_addr.any {
            return true;
        }

        if let Some(rule_ip) = rule_addr.ip {
            if ip == rule_ip {
                return true;
            }
        }

        if let Some(ref subnet) = rule_addr.subnet {
            if let Some((network_str, prefix_len)) = parse_cidr(subnet) {
                if ip_matches_cidr(ip, network_str, prefix_len) {
                    return true;
                }
            }
        }

        false
    }

    pub fn port_matches(&self, port: u16, rule_port: &FirewallPort) -> bool {
        if rule_port.any {
            return true;
        }

        if let Some(rule_p) = rule_port.port {
            if port == rule_p {
                return true;
            }
        }

        if let Some((low, high)) = rule_port.range {
            if port >= low && port <= high {
                return true;
            }
        }

        false
    }

    pub fn check_rate_limit(&mut self, src_ip: IpAddr) -> FirewallAction {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.config.rate_limit_window_secs as i64);
        let threshold = self.config.rate_limit_threshold;

        let tracker = self.rate_trackers.entry(src_ip).or_insert_with(|| RateLimitTracker {
            source_ip: src_ip,
            connection_times: Vec::new(),
            blocked_until: None,
        });

        if let Some(blocked_until) = tracker.blocked_until {
            if now < blocked_until {
                tracing::warn!(src = %src_ip, "IP is rate-limit blocked");
                return FirewallAction::Block;
            }
            tracker.blocked_until = None;
        }

        tracker.connection_times.retain(|t| now - *t < window);
        tracker.connection_times.push(now);

        if tracker.connection_times.len() as u32 > threshold {
            let blocked_until = now + window;
            tracker.blocked_until = Some(blocked_until);
            tracing::warn!(
                src = %src_ip,
                connections = tracker.connection_times.len(),
                threshold = threshold,
                "Rate limit exceeded, blocking IP"
            );
            return FirewallAction::Block;
        }

        FirewallAction::Allow
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        tracing::info!(rule_id = %rule.id, rule_name = %rule.name, "Adding firewall rule");
        self.rule_stats.insert(
            rule.id.clone(),
            RuleStats {
                rule_id: rule.id.clone(),
                hits: 0,
                last_hit: None,
                blocked: 0,
                allowed: 0,
            },
        );
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rule_stats.remove(rule_id);
        let removed = self.rules.len() < before;
        if removed {
            tracing::info!(rule_id = rule_id, "Removed firewall rule");
        }
        removed
    }

    pub fn toggle_rule(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            tracing::info!(rule_id = rule_id, enabled = enabled, "Toggled firewall rule");
            true
        } else {
            false
        }
    }

    pub fn get_rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    pub fn rule_stats(&self) -> &HashMap<String, RuleStats> {
        &self.rule_stats
    }

    pub fn blocked_count(&self) -> u64 {
        self.blocked_count
    }

    pub fn allowed_count(&self) -> u64 {
        self.allowed_count
    }

    pub fn clear_connections(&mut self) {
        self.connections.clear();
        tracing::info!("Cleared all active connections");
    }
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let network: IpAddr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;
    Some((network, prefix_len))
}

fn ip_matches_cidr(ip: IpAddr, network: IpAddr, prefix_len: u32) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) => {
            let ip_bits = u32::from_be_bytes(ip_v4.octets());
            let net_bits = u32::from_be_bytes(net_v4.octets());
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip_v6), IpAddr::V6(net_v6)) => {
            let ip_bits = u128::from_be_bytes(ip_v6.octets());
            let net_bits = u128::from_be_bytes(net_v6.octets());
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn external_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    }

    fn private_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn test_new_has_default_rules() {
        let fw = HostFirewall::new();
        assert!(fw.rules.len() >= 8);
        assert!(fw.rule_stats.contains_key("FW-001"));
        assert!(fw.rule_stats.contains_key("FW-002"));
        assert!(fw.rule_stats.contains_key("FW-003"));
        assert!(fw.rule_stats.contains_key("FW-004"));
        assert!(fw.rule_stats.contains_key("FW-005"));
        assert!(fw.rule_stats.contains_key("FW-006"));
        assert!(fw.rule_stats.contains_key("FW-007"));
    }

    #[test]
    fn test_evaluate_connection_allows_loopback() {
        let mut fw = HostFirewall::new();
        let verdict = fw.evaluate_connection(
            localhost(),
            localhost(),
            12345,
            80,
            Protocol::Tcp,
            TrafficDirection::Outbound,
            None,
        );
        assert_eq!(verdict.action, FirewallAction::Allow);
        assert!(verdict.matched);
        assert_eq!(verdict.rule_id.as_deref(), Some("FW-006"));
    }

    #[test]
    fn test_evaluate_connection_blocks_external_smb() {
        let mut fw = HostFirewall::new();
        let verdict = fw.evaluate_connection(
            external_ip(),
            private_ip(),
            12345,
            445,
            Protocol::Tcp,
            TrafficDirection::Inbound,
            None,
        );
        assert_eq!(verdict.action, FirewallAction::Block);
        assert!(verdict.matched);
        assert_eq!(verdict.rule_id.as_deref(), Some("FW-001"));
    }

    #[test]
    fn test_evaluate_connection_blocks_malicious_port() {
        let mut fw = HostFirewall::new();
        let verdict = fw.evaluate_connection(
            private_ip(),
            external_ip(),
            12345,
            4444,
            Protocol::Tcp,
            TrafficDirection::Outbound,
            None,
        );
        assert_eq!(verdict.action, FirewallAction::Block);
        assert!(verdict.matched);
    }

    #[test]
    fn test_evaluate_connection_allows_normal_https() {
        let mut fw = HostFirewall::new();
        let verdict = fw.evaluate_connection(
            private_ip(),
            external_ip(),
            12345,
            443,
            Protocol::Tcp,
            TrafficDirection::Outbound,
            None,
        );
        assert_eq!(verdict.action, FirewallAction::Allow);
    }

    #[test]
    fn test_ip_matches_exact() {
        let fw = HostFirewall::new();
        let addr = FirewallAddress {
            ip: Some(external_ip()),
            subnet: None,
            any: false,
        };
        assert!(fw.ip_matches(external_ip(), &addr));
        assert!(!fw.ip_matches(private_ip(), &addr));
    }

    #[test]
    fn test_ip_matches_cidr() {
        let fw = HostFirewall::new();
        let addr = FirewallAddress {
            ip: None,
            subnet: Some("10.0.0.0/8".to_string()),
            any: false,
        };
        assert!(fw.ip_matches(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), &addr));
        assert!(fw.ip_matches(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)), &addr));
        assert!(!fw.ip_matches(external_ip(), &addr));
    }

    #[test]
    fn test_ip_matches_any() {
        let fw = HostFirewall::new();
        let addr = FirewallAddress { ip: None, subnet: None, any: true };
        assert!(fw.ip_matches(external_ip(), &addr));
        assert!(fw.ip_matches(private_ip(), &addr));
        assert!(fw.ip_matches(localhost(), &addr));
    }

    #[test]
    fn test_port_matches_exact() {
        let fw = HostFirewall::new();
        let fp = FirewallPort { port: Some(443), range: None, any: false };
        assert!(fw.port_matches(443, &fp));
        assert!(!fw.port_matches(80, &fp));
    }

    #[test]
    fn test_port_matches_range() {
        let fw = HostFirewall::new();
        let fp = FirewallPort { port: None, range: Some((139, 445)), any: false };
        assert!(fw.port_matches(139, &fp));
        assert!(fw.port_matches(445, &fp));
        assert!(fw.port_matches(300, &fp));
        assert!(!fw.port_matches(80, &fp));
    }

    #[test]
    fn test_port_matches_any() {
        let fw = HostFirewall::new();
        let fp = FirewallPort { port: None, range: None, any: true };
        assert!(fw.port_matches(1, &fp));
        assert!(fw.port_matches(65535, &fp));
    }

    #[test]
    fn test_check_rate_limit_blocks_excessive() {
        let mut fw = HostFirewall::new();
        let ip = external_ip();
        for _ in 0..100 {
            fw.check_rate_limit(ip);
        }
        let verdict = fw.check_rate_limit(ip);
        assert_eq!(verdict, FirewallAction::Block);
    }

    #[test]
    fn test_is_loopback() {
        assert!(HostFirewall::is_loopback(localhost()));
        assert!(HostFirewall::is_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(HostFirewall::is_loopback(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!HostFirewall::is_loopback(external_ip()));
    }

    #[test]
    fn test_is_external_ip() {
        assert!(HostFirewall::is_external_ip(external_ip()));
        assert!(!HostFirewall::is_external_ip(private_ip()));
        assert!(!HostFirewall::is_external_ip(localhost()));
        assert!(!HostFirewall::is_external_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!HostFirewall::is_external_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_toggle_rule() {
        let mut fw = HostFirewall::new();
        assert!(fw.toggle_rule("FW-001", false));
        let rule = fw.rules.iter().find(|r| r.id == "FW-001").unwrap();
        assert!(!rule.enabled);
        assert!(fw.toggle_rule("FW-001", true));
        let rule = fw.rules.iter().find(|r| r.id == "FW-001").unwrap();
        assert!(rule.enabled);
        assert!(!fw.toggle_rule("NONEXISTENT", true));
    }

    #[test]
    fn test_blocked_and_allowed_counts() {
        let mut fw = HostFirewall::new();
        assert_eq!(fw.blocked_count(), 0);
        assert_eq!(fw.allowed_count(), 0);

        fw.evaluate_connection(
            external_ip(),
            private_ip(),
            12345,
            445,
            Protocol::Tcp,
            TrafficDirection::Inbound,
            None,
        );
        assert_eq!(fw.blocked_count(), 1);

        fw.evaluate_connection(
            localhost(),
            localhost(),
            12345,
            80,
            Protocol::Tcp,
            TrafficDirection::Outbound,
            None,
        );
        assert_eq!(fw.allowed_count(), 1);
    }

    #[test]
    fn test_rule_stats() {
        let mut fw = HostFirewall::new();
        fw.evaluate_connection(
            external_ip(),
            private_ip(),
            12345,
            445,
            Protocol::Tcp,
            TrafficDirection::Inbound,
            None,
        );
        let stats = fw.rule_stats().get("FW-001").unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.blocked, 1);
        assert!(stats.last_hit.is_some());
    }

    #[test]
    fn test_add_and_remove_rule() {
        let mut fw = HostFirewall::new();
        let initial_count = fw.get_rules().len();
        let rule = FirewallRule {
            id: "FW-CUSTOM".to_string(),
            name: "Custom Rule".to_string(),
            priority: 200,
            action: FirewallAction::Allow,
            enabled: true,
            source: None,
            destination: None,
            protocol: None,
            port: None,
            process_name: None,
            direction: TrafficDirection::Both,
            description: "Test".to_string(),
        };
        fw.add_rule(rule);
        assert_eq!(fw.get_rules().len(), initial_count + 1);
        assert!(fw.remove_rule("FW-CUSTOM"));
        assert_eq!(fw.get_rules().len(), initial_count);
        assert!(!fw.remove_rule("FW-CUSTOM"));
    }

    #[test]
    fn test_clear_connections() {
        let mut fw = HostFirewall::new();
        fw.connections.insert(
            "test".to_string(),
            ConnectionState {
                src_ip: localhost(),
                dst_ip: external_ip(),
                src_port: 1234,
                dst_port: 80,
                protocol: Protocol::Tcp,
                process_name: None,
                process_pid: None,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                bytes_in: 0,
                bytes_out: 0,
                action: FirewallAction::Allow,
            },
        );
        assert_eq!(fw.connections.len(), 1);
        fw.clear_connections();
        assert_eq!(fw.connections.len(), 0);
    }

    #[test]
    fn test_evaluate_network_event() {
        let mut fw = HostFirewall::new();
        let event = NetworkEvent {
            src_ip: Some(localhost()),
            dst_ip: Some(localhost()),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            bytes_in: 1024,
            bytes_out: 512,
            process_name: None,
            process_pid: None,
            timestamp: Utc::now(),
        };
        let verdict = fw.evaluate_network_event(&event);
        assert_eq!(verdict.action, FirewallAction::Allow);
    }

    #[test]
    fn test_default_config() {
        let config = FirewallConfig::default();
        assert_eq!(config.default_action, FirewallAction::Allow);
        assert!(config.enable_logging);
        assert_eq!(config.max_connections, 10_000);
        assert_eq!(config.rate_limit_window_secs, 60);
        assert_eq!(config.rate_limit_threshold, 100);
        assert!(config.enable_auto_block);
    }

    #[test]
    fn test_custom_config() {
        let config = FirewallConfig {
            default_action: FirewallAction::Block,
            enable_logging: false,
            max_connections: 500,
            rate_limit_window_secs: 30,
            rate_limit_threshold: 50,
            enable_auto_block: false,
        };
        let fw = HostFirewall::with_config(config);
        assert_eq!(fw.config.default_action, FirewallAction::Block);
        assert!(!fw.config.enable_logging);
        assert_eq!(fw.config.max_connections, 500);
    }
}
