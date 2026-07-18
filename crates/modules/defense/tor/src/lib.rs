pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{DnsEvent, EventSeverity, NetworkEvent, ProcessInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TorIndicatorType {
    KnownExitNode,
    KnownBridge,
    TorPort,
    DnsQuery,
    ProcessName,
    TrafficPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorIndicator {
    pub indicator_type: TorIndicatorType,
    pub value: String,
    pub confidence: f32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorDetection {
    pub ip: IpAddr,
    pub port: u16,
    pub confidence: f32,
    pub indicators: Vec<TorIndicator>,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
}

pub struct TorDetector {
    exit_nodes: HashSet<IpAddr>,
    bridges: HashSet<IpAddr>,
    tor_ports: HashSet<u16>,
    tor_process_names: HashSet<String>,
    tor_dns_suffixes: Vec<String>,
    detection_count: u64,
}

impl TorDetector {
    pub fn new() -> Self {
        let mut exit_nodes = HashSet::new();
        exit_nodes.insert("185.220.101.1".parse().unwrap());
        exit_nodes.insert("185.220.101.2".parse().unwrap());
        exit_nodes.insert("209.148.46.249".parse().unwrap());

        let mut bridges = HashSet::new();
        bridges.insert("109.192.200.111".parse().unwrap());

        let mut tor_ports = HashSet::new();
        tor_ports.insert(9001);
        tor_ports.insert(9030);
        tor_ports.insert(443);

        let mut tor_process_names = HashSet::new();
        tor_process_names.insert("tor.exe".to_string());
        tor_process_names.insert("tor".to_string());
        tor_process_names.insert("torsocks".to_string());
        tor_process_names.insert("obfs4proxy".to_string());
        tor_process_names.insert("lyrebird".to_string());

        let tor_dns_suffixes = vec![
            ".onion".to_string(),
            ".torproject.org".to_string(),
            "dns4torpnlfskhgvrnt62ist22jipyhtevozqfzycmldjqeaaymvdzi3ad".to_string(),
        ];

        info!("TorDetector initialized with {} exit nodes, {} bridges",
            exit_nodes.len(), bridges.len());

        Self {
            exit_nodes,
            bridges,
            tor_ports,
            tor_process_names,
            tor_dns_suffixes,
            detection_count: 0,
        }
    }

    pub fn check_network(&mut self, event: &NetworkEvent) -> Vec<TorDetection> {
        let mut detections = Vec::new();

        let dst_ip = match event.dst_ip {
            Some(ip) => ip,
            None => return detections,
        };

        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;

        if self.exit_nodes.contains(&dst_ip) {
            indicators.push(TorIndicator {
                indicator_type: TorIndicatorType::KnownExitNode,
                value: dst_ip.to_string(),
                confidence: 0.95,
                source: "exit-node-list".to_string(),
            });
            confidence += 0.45;
        }

        if self.bridges.contains(&dst_ip) {
            indicators.push(TorIndicator {
                indicator_type: TorIndicatorType::KnownBridge,
                value: dst_ip.to_string(),
                confidence: 0.9,
                source: "bridge-list".to_string(),
            });
            confidence += 0.45;
        }

        if self.tor_ports.contains(&event.dst_port) {
            indicators.push(TorIndicator {
                indicator_type: TorIndicatorType::TorPort,
                value: event.dst_port.to_string(),
                confidence: 0.6,
                source: "port-analysis".to_string(),
            });
            confidence += 0.2;
        }

        if !indicators.is_empty() {
            let total = indicators.len() as f32;
            let avg_confidence = indicators.iter().map(|i| i.confidence).sum::<f32>() / total;
            let final_confidence = confidence.min(1.0).max(avg_confidence);

            let severity = if final_confidence > 0.8 {
                EventSeverity::High
            } else if final_confidence > 0.5 {
                EventSeverity::Medium
            } else {
                EventSeverity::Low
            };

            detections.push(TorDetection {
                ip: dst_ip,
                port: event.dst_port,
                confidence: final_confidence,
                indicators,
                severity,
                timestamp: Utc::now(),
            });

            self.detection_count += 1;
            warn!(
                ip = %dst_ip,
                port = event.dst_port,
                confidence = final_confidence,
                "Tor network activity detected"
            );
        }

        detections
    }

    pub fn check_process(&mut self, info: &ProcessInfo) -> Vec<TorDetection> {
        let mut detections = Vec::new();

        let name_lower = info.name.to_lowercase();

        for tor_name in &self.tor_process_names {
            if name_lower == tor_name.to_lowercase() {
                let indicator = TorIndicator {
                    indicator_type: TorIndicatorType::ProcessName,
                    value: info.name.clone(),
                    confidence: 0.9,
                    source: "process-monitor".to_string(),
                };

                detections.push(TorDetection {
                    ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                    port: 0,
                    confidence: 0.85,
                    indicators: vec![indicator],
                    severity: EventSeverity::Medium,
                    timestamp: Utc::now(),
                });

                self.detection_count += 1;
                warn!(name = %info.name, pid = info.pid, "Tor process detected");
                break;
            }
        }

        let cmd_lower = info.command_line.to_lowercase();
        if cmd_lower.contains("--ssocks") || cmd_lower.contains("-f /etc/tor") || cmd_lower.contains("onion") {
            let indicator = TorIndicator {
                indicator_type: TorIndicatorType::TrafficPattern,
                value: info.command_line.clone(),
                confidence: 0.8,
                source: "command-line-analysis".to_string(),
            };

            detections.push(TorDetection {
                ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                port: 0,
                confidence: 0.75,
                indicators: vec![indicator],
                severity: EventSeverity::Medium,
                timestamp: Utc::now(),
            });

            self.detection_count += 1;
        }

        detections
    }

    pub fn check_dns(&mut self, event: &DnsEvent) -> Vec<TorDetection> {
        let mut detections = Vec::new();

        let query_lower = event.query.to_lowercase();

        for suffix in &self.tor_dns_suffixes {
            if query_lower.ends_with(suffix) {
                let indicator = TorIndicator {
                    indicator_type: TorIndicatorType::DnsQuery,
                    value: event.query.clone(),
                    confidence: 0.95,
                    source: "dns-monitor".to_string(),
                };

                let confidence = 0.9;
                let severity = EventSeverity::High;

                detections.push(TorDetection {
                    ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                    port: 0,
                    confidence,
                    indicators: vec![indicator],
                    severity,
                    timestamp: Utc::now(),
                });

                self.detection_count += 1;
                warn!(query = %event.query, "Tor DNS query detected");
                break;
            }
        }

        detections
    }

    pub fn add_exit_node(&mut self, ip: IpAddr) {
        info!(ip = %ip, "Adding Tor exit node");
        self.exit_nodes.insert(ip);
    }

    pub fn add_bridge(&mut self, ip: IpAddr) {
        info!(ip = %ip, "Adding Tor bridge");
        self.bridges.insert(ip);
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }
}

impl Default for TorDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use royalsecurity_common::types::Protocol;
    use std::net::Ipv4Addr;

    fn make_network_event(dst: IpAddr, port: u16) -> NetworkEvent {
        NetworkEvent {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            dst_ip: Some(dst),
            src_port: 43210,
            dst_port: port,
            protocol: Protocol::Tcp,
            bytes_in: 1024,
            bytes_out: 512,
            process_name: Some("tor.exe".to_string()),
            process_pid: Some(1234),
            timestamp: Utc::now(),
        }
    }

    fn make_process(name: &str, cmd: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 5678,
            ppid: 1,
            name: name.to_string(),
            path: format!("C:\\{}", name),
            command_line: cmd.to_string(),
            user: "user".to_string(),
            hash_sha256: None,
            integrity_level: None,
            timestamp: Utc::now(),
        }
    }

    fn make_dns(query: &str) -> DnsEvent {
        DnsEvent {
            query: query.to_string(),
            query_type: "A".to_string(),
            response: None,
            response_code: Some("NOERROR".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_tor_detector_new() {
        let detector = TorDetector::new();
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn test_check_network_exit_node_detected() {
        let mut detector = TorDetector::new();
        let event = make_network_event(
            IpAddr::V4(Ipv4Addr::new(185, 220, 101, 1)),
            9001,
        );
        let detections = detector.check_network(&event);
        assert_eq!(detections.len(), 1);
        assert!(detections[0].confidence > 0.5);
        assert_eq!(detections[0].indicators.len(), 2);
        assert_eq!(detector.detection_count(), 1);
    }

    #[test]
    fn test_check_network_normal_traffic_no_detection() {
        let mut detector = TorDetector::new();
        let event = make_network_event(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
        );
        let detections = detector.check_network(&event);
        assert!(detections.is_empty());
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn test_check_network_bridge_detected() {
        let mut detector = TorDetector::new();
        let event = make_network_event(
            IpAddr::V4(Ipv4Addr::new(109, 192, 200, 111)),
            443,
        );
        let detections = detector.check_network(&event);
        assert_eq!(detections.len(), 1);
        assert!(detections[0].indicators.iter().any(|i| i.indicator_type == TorIndicatorType::KnownBridge));
    }

    #[test]
    fn test_check_process_tor_binary() {
        let mut detector = TorDetector::new();
        let info = make_process("tor.exe", "C:\\tor.exe");
        let detections = detector.check_process(&info);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].severity, EventSeverity::Medium);
        assert_eq!(detector.detection_count(), 1);
    }

    #[test]
    fn test_check_process_normal_not_detected() {
        let mut detector = TorDetector::new();
        let info = make_process("chrome.exe", "C:\\chrome.exe");
        let detections = detector.check_process(&info);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_check_dns_onion_domain() {
        let mut detector = TorDetector::new();
        let event = make_dns("abc123.onion");
        let detections = detector.check_dns(&event);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].confidence, 0.9);
        assert_eq!(detector.detection_count(), 1);
    }

    #[test]
    fn test_check_dns_normal_not_detected() {
        let mut detector = TorDetector::new();
        let event = make_dns("www.google.com");
        let detections = detector.check_dns(&event);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_add_exit_node_and_bridge() {
        let mut detector = TorDetector::new();
        let custom_ip: IpAddr = "1.2.3.4".parse().unwrap();
        detector.add_exit_node(custom_ip);
        detector.add_bridge(custom_ip);

        let event = make_network_event(custom_ip, 9001);
        let detections = detector.check_network(&event);
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_check_process_obfs4proxy() {
        let mut detector = TorDetector::new();
        let info = make_process("obfs4proxy", "/usr/bin/obfs4proxy");
        let detections = detector.check_process(&info);
        assert_eq!(detections.len(), 1);
        assert_eq!(detector.detection_count(), 1);
    }

    #[test]
    fn test_detection_count_accumulates() {
        let mut detector = TorDetector::new();
        let event1 = make_network_event(IpAddr::V4(Ipv4Addr::new(185, 220, 101, 1)), 9001);
        let event2 = make_network_event(IpAddr::V4(Ipv4Addr::new(185, 220, 101, 2)), 443);
        detector.check_network(&event1);
        detector.check_network(&event2);
        assert_eq!(detector.detection_count(), 2);
    }

    #[test]
    fn test_check_dns_torproject() {
        let mut detector = TorDetector::new();
        let event = make_dns("check.torproject.org");
        let detections = detector.check_dns(&event);
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_no_dst_ip() {
        let mut detector = TorDetector::new();
        let event = NetworkEvent {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dst_ip: None,
            src_port: 1234,
            dst_port: 9001,
            protocol: Protocol::Tcp,
            bytes_in: 0,
            bytes_out: 0,
            process_name: None,
            process_pid: None,
            timestamp: Utc::now(),
        };
        let detections = detector.check_network(&event);
        assert!(detections.is_empty());
    }
}
