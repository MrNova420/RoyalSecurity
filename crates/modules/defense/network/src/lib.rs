pub mod prelude;

use royalsecurity_common::types::{EventSeverity, NetworkEvent, Protocol};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enable_flow_tracking: bool,
    pub enable_port_scan_detection: bool,
    pub enable_protocol_anomaly: bool,
    pub port_scan_threshold: u32,
    pub port_scan_window_secs: u64,
    pub connection_threshold: u32,
    pub large_transfer_threshold: u64,
    pub max_flows: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_flow_tracking: true,
            enable_port_scan_detection: true,
            enable_protocol_anomaly: true,
            port_scan_threshold: 20,
            port_scan_window_secs: 60,
            connection_threshold: 1000,
            large_transfer_threshold: 104857600,
            max_flows: 50000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub flow_id: String,
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
    pub packets_in: u64,
    pub packets_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanTracker {
    pub source_ip: IpAddr,
    pub target_ports: HashSet<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub unique_targets: HashSet<IpAddr>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanType {
    SynScan,
    ConnectScan,
    UdpScan,
    FinScan,
    XmasScan,
    NullScan,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkThreatType {
    PortScan,
    SynFlood,
    Ddos,
    DataExfiltration,
    CncCommunication,
    LateralMovement,
    InternalRecon,
    SuspiciousProtocol,
    LargeTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDetection {
    pub id: Uuid,
    pub threat_type: NetworkThreatType,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficStats {
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_connections: u64,
    pub active_flows: u64,
    pub unique_sources: HashSet<String>,
    pub unique_destinations: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomaly {
    pub expected_protocol: Protocol,
    pub actual_protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub description: String,
}

pub struct NetworkMonitor {
    flows: HashMap<String, NetworkFlow>,
    port_scan_trackers: HashMap<IpAddr, PortScanTracker>,
    detections: Vec<NetworkDetection>,
    traffic_stats: TrafficStats,
    config: NetworkConfig,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        info!("NetworkMonitor initialized with default configuration");
        Self {
            flows: HashMap::new(),
            port_scan_trackers: HashMap::new(),
            detections: Vec::new(),
            traffic_stats: TrafficStats::default(),
            config: NetworkConfig::default(),
        }
    }

    pub fn with_config(config: NetworkConfig) -> Self {
        info!(
            "NetworkMonitor initialized: port_scan_threshold={}, connection_threshold={}, max_flows={}",
            config.port_scan_threshold, config.connection_threshold, config.max_flows
        );
        Self {
            flows: HashMap::new(),
            port_scan_trackers: HashMap::new(),
            detections: Vec::new(),
            traffic_stats: TrafficStats::default(),
            config,
        }
    }

    pub fn analyze_network_event(&mut self, event: &NetworkEvent) -> Vec<NetworkDetection> {
        let mut detections = Vec::new();

        self.traffic_stats.total_bytes_in += event.bytes_in;
        self.traffic_stats.total_bytes_out += event.bytes_out;

        if let Some(ref src_ip) = event.src_ip {
            self.traffic_stats
                .unique_sources
                .insert(src_ip.to_string());
        }
        if let Some(ref dst_ip) = event.dst_ip {
            self.traffic_stats
                .unique_destinations
                .insert(dst_ip.to_string());
        }

        let src_ip = match event.src_ip {
            Some(ip) => ip,
            None => return detections,
        };
        let dst_ip = match event.dst_ip {
            Some(ip) => ip,
            None => return detections,
        };

        if self.config.enable_flow_tracking {
            if let Some(flow) = self.update_flow(event) {
                debug!("Flow updated: {}", flow.flow_id);
            }
        }

        if self.config.enable_port_scan_detection {
            let now = event.timestamp;
            let window_duration =
                chrono::Duration::seconds(self.config.port_scan_window_secs as i64);

            let tracker = self.port_scan_trackers.entry(src_ip).or_insert_with(|| {
                debug!("New port scan tracker for source {}", src_ip);
                PortScanTracker {
                    source_ip: src_ip,
                    target_ports: HashSet::new(),
                    first_seen: now,
                    last_seen: now,
                    unique_targets: HashSet::new(),
                }
            });

            if (now - tracker.first_seen) > window_duration {
                debug!(
                    "Resetting port scan tracker for {} (window expired)",
                    src_ip
                );
                tracker.target_ports.clear();
                tracker.unique_targets.clear();
                tracker.first_seen = now;
            }

            tracker.target_ports.insert(event.dst_port);
            tracker.unique_targets.insert(dst_ip);
            tracker.last_seen = now;

            if let Some(detection) = Self::detect_port_scan(tracker, self.config.port_scan_threshold) {
                warn!(
                    "Port scan detected from {}: {} unique ports, confidence: {:.2}",
                    src_ip,
                    tracker.target_ports.len(),
                    detection.confidence
                );
                self.detections.push(detection.clone());
                detections.push(detection);
                tracker.target_ports.clear();
                tracker.unique_targets.clear();
                tracker.first_seen = now;
            }
        }

        if let Some(detection) = self.detect_large_transfer(event) {
            warn!(
                "Large transfer detected: {} bytes out, confidence: {:.2}",
                event.bytes_out, detection.confidence
            );
            self.detections.push(detection.clone());
            detections.push(detection);
        }

        if self.config.enable_protocol_anomaly {
            if let Some(anomaly) = Self::detect_protocol_anomaly(event) {
                let detection = NetworkDetection {
                    id: Uuid::new_v4(),
                    threat_type: NetworkThreatType::SuspiciousProtocol,
                    severity: EventSeverity::Medium,
                    confidence: 0.7,
                    source_ip: event.src_ip,
                    destination_ip: event.dst_ip,
                    process_name: event.process_name.clone(),
                    process_pid: event.process_pid,
                    description: format!("Protocol anomaly: {}", anomaly.description),
                    evidence: vec![
                        format!("Expected protocol: {:?}", anomaly.expected_protocol),
                        format!("Actual protocol: {:?}", anomaly.actual_protocol),
                        format!("Source port: {}", anomaly.src_port),
                        format!("Destination port: {}", anomaly.dst_port),
                    ],
                    timestamp: Utc::now(),
                };
                warn!("Protocol anomaly detected: {}", anomaly.description);
                self.detections.push(detection.clone());
                detections.push(detection);
            }
        }

        if self.config.enable_flow_tracking {
            if let Some(ref process_name) = event.process_name {
                if let Some(process_pid) = event.process_pid {
                    let flows: Vec<NetworkFlow> = self
                        .flows
                        .values()
                        .filter(|f| f.process_pid == Some(process_pid))
                        .cloned()
                        .collect();

                    if let Some(detection) =
                        self.detect_connection_flood(process_name, process_pid, &flows)
                    {
                        warn!(
                            "Connection flood detected from process {} (PID {}): confidence {:.2}",
                            process_name, process_pid, detection.confidence
                        );
                        self.detections.push(detection.clone());
                        detections.push(detection);
                    }
                }
            }
        }

        self.traffic_stats.total_connections += 1;
        detections
    }

    pub fn detect_port_scan(tracker: &PortScanTracker, threshold: u32) -> Option<NetworkDetection> {
        let port_count = tracker.target_ports.len() as u32;
        if port_count < threshold {
            return None;
        }

        let elapsed = (tracker.last_seen - tracker.first_seen).num_seconds() as u64;
        let target_count = tracker.unique_targets.len() as u32;

        let confidence = if port_count > threshold * 3 {
            0.95
        } else if port_count > threshold * 2 {
            0.85
        } else {
            0.7
        };

        let severity = if port_count > threshold * 3 {
            EventSeverity::Critical
        } else if port_count > threshold * 2 {
            EventSeverity::High
        } else {
            EventSeverity::Medium
        };

        let scan_type = ScanType::SynScan;

        Some(NetworkDetection {
            id: Uuid::new_v4(),
            threat_type: NetworkThreatType::PortScan,
            severity,
            confidence,
            source_ip: Some(tracker.source_ip),
            destination_ip: None,
            process_name: None,
            process_pid: None,
            description: format!(
                "Port scan detected from {}: {} unique ports scanned across {} targets in {}s (type: {:?})",
                tracker.source_ip, port_count, target_count, elapsed, scan_type
            ),
            evidence: vec![
                format!("Unique ports scanned: {}", port_count),
                format!("Unique target IPs: {}", target_count),
                format!("Time window: {}s", elapsed),
                format!("Scan type: {:?}", scan_type),
                format!("Source: {}", tracker.source_ip),
            ],
            timestamp: Utc::now(),
        })
    }

    pub fn detect_connection_flood(
        &self,
        process_name: &str,
        process_pid: u32,
        connections: &[NetworkFlow],
    ) -> Option<NetworkDetection> {
        let unique_destinations: HashSet<IpAddr> =
            connections.iter().map(|f| f.dst_ip).collect();
        let dest_count = unique_destinations.len() as u32;

        if dest_count < self.config.connection_threshold {
            return None;
        }

        let confidence = if dest_count > self.config.connection_threshold * 2 {
            0.9
        } else {
            0.75
        };

        let severity = if dest_count > self.config.connection_threshold * 2 {
            EventSeverity::High
        } else {
            EventSeverity::Medium
        };

        let dest_list: Vec<String> = unique_destinations
            .iter()
            .take(10)
            .map(|ip| ip.to_string())
            .collect();

        Some(NetworkDetection {
            id: Uuid::new_v4(),
            threat_type: NetworkThreatType::LateralMovement,
            severity,
            confidence,
            source_ip: None,
            destination_ip: None,
            process_name: Some(process_name.to_string()),
            process_pid: Some(process_pid),
            description: format!(
                "Connection flood from process {} (PID {}): {} unique destinations",
                process_name, process_pid, dest_count
            ),
            evidence: vec![
                format!("Unique destinations: {}", dest_count),
                format!("Total connections: {}", connections.len()),
                format!("Sample destinations: {}", dest_list.join(", ")),
            ],
            timestamp: Utc::now(),
        })
    }

    pub fn detect_large_transfer(&self, event: &NetworkEvent) -> Option<NetworkDetection> {
        if event.bytes_out <= self.config.large_transfer_threshold {
            return None;
        }

        let severity = if event.bytes_out > self.config.large_transfer_threshold * 10 {
            EventSeverity::Critical
        } else if event.bytes_out > self.config.large_transfer_threshold * 5 {
            EventSeverity::High
        } else {
            EventSeverity::Medium
        };

        let confidence = if event.bytes_out > self.config.large_transfer_threshold * 5 {
            0.9
        } else {
            0.7
        };

        Some(NetworkDetection {
            id: Uuid::new_v4(),
            threat_type: NetworkThreatType::DataExfiltration,
            severity,
            confidence,
            source_ip: event.src_ip,
            destination_ip: event.dst_ip,
            process_name: event.process_name.clone(),
            process_pid: event.process_pid,
            description: format!(
                "Large data transfer: {} bytes outbound to {}:{}",
                event.bytes_out,
                event
                    .dst_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                event.dst_port
            ),
            evidence: vec![
                format!("Bytes out: {}", event.bytes_out),
                format!("Threshold: {}", self.config.large_transfer_threshold),
                format!(
                    "Source: {}:{}",
                    event
                        .src_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    event.src_port
                ),
                format!(
                    "Destination: {}:{}",
                    event
                        .dst_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    event.dst_port
                ),
            ],
            timestamp: Utc::now(),
        })
    }

    pub fn detect_protocol_anomaly(event: &NetworkEvent) -> Option<ProtocolAnomaly> {
        if event.dst_port == 53 && event.protocol != Protocol::Udp {
            return Some(ProtocolAnomaly {
                expected_protocol: Protocol::Udp,
                actual_protocol: event.protocol,
                src_port: event.src_port,
                dst_port: event.dst_port,
                description: format!(
                    "DNS traffic on port 53 using {:?} instead of UDP",
                    event.protocol
                ),
            });
        }

        if (event.dst_port == 80 || event.dst_port == 443) && event.protocol != Protocol::Tcp {
            return Some(ProtocolAnomaly {
                expected_protocol: Protocol::Tcp,
                actual_protocol: event.protocol,
                src_port: event.src_port,
                dst_port: event.dst_port,
                description: format!(
                    "HTTP/HTTPS traffic on port {} using {:?} instead of TCP",
                    event.dst_port, event.protocol
                ),
            });
        }

        None
    }

    pub fn generate_flow_id(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> String {
        let mut hasher = DefaultHasher::new();
        src_ip.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        protocol.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
                    || (octets[0] == 192 && octets[1] == 168)
                    || octets[0] == 127
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    pub fn update_flow(&mut self, event: &NetworkEvent) -> Option<NetworkFlow> {
        let src_ip = event.src_ip?;
        let dst_ip = event.dst_ip?;

        let flow_id =
            Self::generate_flow_id(src_ip, dst_ip, event.src_port, event.dst_port, event.protocol);

        if self.flows.len() >= self.config.max_flows {
            if let Some(oldest_key) = self
                .flows
                .iter()
                .min_by_key(|(_, f)| f.last_seen)
                .map(|(k, _)| k.clone())
            {
                debug!("Evicting oldest flow: {}", oldest_key);
                self.flows.remove(&oldest_key);
            }
        }

        let flow = self.flows.entry(flow_id.clone()).or_insert_with(|| {
            debug!("New flow: {}", flow_id);
            NetworkFlow {
                flow_id: flow_id.clone(),
                src_ip,
                dst_ip,
                src_port: event.src_port,
                dst_port: event.dst_port,
                protocol: event.protocol,
                process_name: event.process_name.clone(),
                process_pid: event.process_pid,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                bytes_in: 0,
                bytes_out: 0,
                packets_in: 0,
                packets_out: 0,
            }
        });

        flow.last_seen = event.timestamp;
        flow.bytes_in += event.bytes_in;
        flow.bytes_out += event.bytes_out;
        flow.packets_in += 1;
        flow.packets_out += 1;

        Some(flow.clone())
    }

    pub fn get_active_flows(&self) -> Vec<&NetworkFlow> {
        self.flows.values().collect()
    }

    pub fn get_flows_for_process(&self, pid: u32) -> Vec<&NetworkFlow> {
        self.flows
            .values()
            .filter(|f| f.process_pid == Some(pid))
            .collect()
    }

    pub fn traffic_stats(&self) -> &TrafficStats {
        &self.traffic_stats
    }

    pub fn detection_count(&self) -> u64 {
        self.detections.len() as u64
    }

    pub fn clear(&mut self) {
        self.flows.clear();
        self.port_scan_trackers.clear();
        self.detections.clear();
        self.traffic_stats = TrafficStats::default();
        info!("NetworkMonitor state cleared");
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        bytes_out: u64,
    ) -> NetworkEvent {
        NetworkEvent {
            src_ip: Some(src.parse::<IpAddr>().unwrap()),
            dst_ip: Some(dst.parse::<IpAddr>().unwrap()),
            src_port,
            dst_port,
            protocol,
            bytes_in: 0,
            bytes_out,
            process_name: Some("test.exe".to_string()),
            process_pid: Some(1000),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_network_monitor_new() {
        let monitor = NetworkMonitor::new();
        assert_eq!(monitor.detection_count(), 0);
        assert!(monitor.flows.is_empty());
        assert!(monitor.port_scan_trackers.is_empty());
        assert_eq!(monitor.traffic_stats.total_bytes_in, 0);
        assert_eq!(monitor.traffic_stats.total_bytes_out, 0);
        assert_eq!(monitor.config.port_scan_threshold, 20);
        assert_eq!(monitor.config.connection_threshold, 1000);
        assert_eq!(monitor.config.large_transfer_threshold, 104857600);
    }

    #[test]
    fn test_analyze_network_event_detects_port_scan() {
        let mut monitor = NetworkMonitor::new();
        let base = Utc::now();
        let mut scan_detected = false;

        for i in 0..25u16 {
            let event = NetworkEvent {
                src_ip: Some("10.0.0.100".parse().unwrap()),
                dst_ip: Some("192.168.1.1".parse().unwrap()),
                src_port: 12345,
                dst_port: 1000 + i,
                protocol: Protocol::Tcp,
                bytes_in: 0,
                bytes_out: 0,
                process_name: Some("nmap.exe".to_string()),
                process_pid: Some(9999),
                timestamp: base,
            };
            let detections = monitor.analyze_network_event(&event);
            if detections
                .iter()
                .any(|d| d.threat_type == NetworkThreatType::PortScan)
            {
                scan_detected = true;
            }
        }
        assert!(
            scan_detected,
            "Should have detected port scan during analysis"
        );
        assert!(monitor.detection_count() > 0);
    }

    #[test]
    fn test_detect_port_scan_high_port_count() {
        let monitor = NetworkMonitor::new();
        let now = Utc::now();
        let source: IpAddr = "10.0.0.100".parse().unwrap();
        let target: IpAddr = "192.168.1.1".parse().unwrap();

        let tracker = PortScanTracker {
            source_ip: source,
            target_ports: (0..25).map(|p| 1000 + p).collect(),
            first_seen: now,
            last_seen: now,
            unique_targets: HashSet::from([target]),
        };

        let detection = NetworkMonitor::detect_port_scan(&tracker, monitor.config.port_scan_threshold);
        assert!(detection.is_some());
        let detection = detection.unwrap();
        assert_eq!(detection.threat_type, NetworkThreatType::PortScan);
        assert!(detection.confidence >= 0.7);
        assert_eq!(detection.source_ip, Some(source));
        assert!(detection
            .evidence
            .iter()
            .any(|e| e.contains("Unique ports scanned: 25")));
    }

    #[test]
    fn test_detect_connection_flood_many_destinations() {
        let config = NetworkConfig {
            connection_threshold: 5,
            ..Default::default()
        };
        let monitor = NetworkMonitor::with_config(config);

        let flows: Vec<NetworkFlow> = (0..10u16)
            .map(|i| {
                NetworkFlow {
                    flow_id: format!("flow_{}", i),
                    src_ip: "10.0.0.100".parse().unwrap(),
                    dst_ip: format!("192.168.1.{}", i + 1).parse().unwrap(),
                    src_port: 12345,
                    dst_port: 80,
                    protocol: Protocol::Tcp,
                    process_name: Some("malware.exe".to_string()),
                    process_pid: Some(1234),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    bytes_in: 100,
                    bytes_out: 100,
                    packets_in: 1,
                    packets_out: 1,
                }
            })
            .collect();

        let detection = monitor.detect_connection_flood("malware.exe", 1234, &flows);
        assert!(detection.is_some());
        let detection = detection.unwrap();
        assert_eq!(
            detection.threat_type,
            NetworkThreatType::LateralMovement
        );
        assert!(detection.confidence >= 0.7);
        assert_eq!(detection.process_name, Some("malware.exe".to_string()));
        assert_eq!(detection.process_pid, Some(1234));
    }

    #[test]
    fn test_detect_large_transfer_over_threshold() {
        let monitor = NetworkMonitor::new();
        let event = NetworkEvent {
            src_ip: Some("10.0.0.100".parse().unwrap()),
            dst_ip: Some("203.0.113.1".parse().unwrap()),
            src_port: 43210,
            dst_port: 443,
            protocol: Protocol::Tcp,
            bytes_in: 1024,
            bytes_out: 200_000_000,
            process_name: Some("suspicious.exe".to_string()),
            process_pid: Some(5678),
            timestamp: Utc::now(),
        };

        let detection = monitor.detect_large_transfer(&event);
        assert!(detection.is_some());
        let detection = detection.unwrap();
        assert_eq!(
            detection.threat_type,
            NetworkThreatType::DataExfiltration
        );
        assert!(detection.confidence >= 0.7);
        assert_eq!(
            detection.source_ip,
            Some("10.0.0.100".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            detection.destination_ip,
            Some("203.0.113.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_detect_protocol_anomaly_dns_on_tcp() {
        let event = NetworkEvent {
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            src_port: 12345,
            dst_port: 53,
            protocol: Protocol::Tcp,
            bytes_in: 0,
            bytes_out: 0,
            process_name: Some("nslookup.exe".to_string()),
            process_pid: Some(100),
            timestamp: Utc::now(),
        };

        let anomaly = NetworkMonitor::detect_protocol_anomaly(&event);
        assert!(anomaly.is_some());
        let anomaly = anomaly.unwrap();
        assert_eq!(anomaly.expected_protocol, Protocol::Udp);
        assert_eq!(anomaly.actual_protocol, Protocol::Tcp);
        assert_eq!(anomaly.dst_port, 53);
    }

    #[test]
    fn test_detect_protocol_anomaly_http_on_udp() {
        let event = NetworkEvent {
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("93.184.216.34".parse().unwrap()),
            src_port: 54321,
            dst_port: 80,
            protocol: Protocol::Udp,
            bytes_in: 0,
            bytes_out: 0,
            process_name: Some("test.exe".to_string()),
            process_pid: Some(200),
            timestamp: Utc::now(),
        };

        let anomaly = NetworkMonitor::detect_protocol_anomaly(&event);
        assert!(anomaly.is_some());
        let anomaly = anomaly.unwrap();
        assert_eq!(anomaly.expected_protocol, Protocol::Tcp);
        assert_eq!(anomaly.actual_protocol, Protocol::Udp);
        assert_eq!(anomaly.dst_port, 80);
    }

    #[test]
    fn test_generate_flow_id_deterministic() {
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "192.168.1.1".parse().unwrap();

        let id1 = NetworkMonitor::generate_flow_id(src, dst, 80, 443, Protocol::Tcp);
        let id2 = NetworkMonitor::generate_flow_id(src, dst, 80, 443, Protocol::Tcp);
        assert_eq!(id1, id2);

        let id3 = NetworkMonitor::generate_flow_id(src, dst, 80, 8080, Protocol::Tcp);
        assert_ne!(id1, id3);

        let id4 = NetworkMonitor::generate_flow_id(dst, src, 80, 443, Protocol::Tcp);
        assert_ne!(id1, id4);
    }

    #[test]
    fn test_is_private_ip_known_ranges() {
        assert!(NetworkMonitor::is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("10.255.255.255".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("192.168.255.255".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(NetworkMonitor::is_private_ip("127.255.255.255".parse().unwrap()));
        assert!(!NetworkMonitor::is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!NetworkMonitor::is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!NetworkMonitor::is_private_ip("203.0.113.1".parse().unwrap()));
        assert!(!NetworkMonitor::is_private_ip("172.32.0.1".parse().unwrap()));
        assert!(!NetworkMonitor::is_private_ip("192.169.0.1".parse().unwrap()));
    }

    #[test]
    fn test_update_flow_creates_and_updates() {
        let mut monitor = NetworkMonitor::new();
        let event1 = NetworkEvent {
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("192.168.1.1".parse().unwrap()),
            src_port: 80,
            dst_port: 443,
            protocol: Protocol::Tcp,
            bytes_in: 100,
            bytes_out: 200,
            process_name: Some("test.exe".to_string()),
            process_pid: Some(1234),
            timestamp: Utc::now(),
        };

        let flow = monitor.update_flow(&event1);
        assert!(flow.is_some());
        let flow = flow.unwrap();
        assert_eq!(flow.bytes_in, 100);
        assert_eq!(flow.bytes_out, 200);
        assert_eq!(flow.packets_in, 1);
        assert_eq!(flow.packets_out, 1);

        let event2 = NetworkEvent {
            bytes_in: 50,
            bytes_out: 100,
            ..event1
        };

        let flow = monitor.update_flow(&event2);
        assert!(flow.is_some());
        let flow = flow.unwrap();
        assert_eq!(flow.bytes_in, 150);
        assert_eq!(flow.bytes_out, 300);
        assert_eq!(flow.packets_in, 2);
        assert_eq!(flow.packets_out, 2);
    }

    #[test]
    fn test_get_flows_for_process_filters() {
        let mut monitor = NetworkMonitor::new();

        for i in 0..5u16 {
            let event = NetworkEvent {
                src_ip: Some("10.0.0.1".parse().unwrap()),
                dst_ip: Some(format!("192.168.1.{}", i + 1).parse().unwrap()),
                src_port: 12345,
                dst_port: 80 + i,
                protocol: Protocol::Tcp,
                bytes_in: 100,
                bytes_out: 100,
                process_name: Some("app1.exe".to_string()),
                process_pid: Some(100),
                timestamp: Utc::now(),
            };
            monitor.update_flow(&event);
        }

        for i in 0..3u16 {
            let event = NetworkEvent {
                src_ip: Some("10.0.0.2".parse().unwrap()),
                dst_ip: Some(format!("192.168.2.{}", i + 1).parse().unwrap()),
                src_port: 54321,
                dst_port: 80 + i,
                protocol: Protocol::Tcp,
                bytes_in: 200,
                bytes_out: 200,
                process_name: Some("app2.exe".to_string()),
                process_pid: Some(200),
                timestamp: Utc::now(),
            };
            monitor.update_flow(&event);
        }

        let flows_100 = monitor.get_flows_for_process(100);
        assert_eq!(flows_100.len(), 5);
        assert!(flows_100
            .iter()
            .all(|f| f.process_pid == Some(100)));

        let flows_200 = monitor.get_flows_for_process(200);
        assert_eq!(flows_200.len(), 3);
        assert!(flows_200
            .iter()
            .all(|f| f.process_pid == Some(200)));

        let flows_999 = monitor.get_flows_for_process(999);
        assert!(flows_999.is_empty());
    }

    #[test]
    fn test_clear_resets_state() {
        let mut monitor = NetworkMonitor::new();
        for i in 0..5u16 {
            let event = NetworkEvent {
                src_ip: Some("10.0.0.1".parse().unwrap()),
                dst_ip: Some("192.168.1.1".parse().unwrap()),
                src_port: 12345,
                dst_port: 80 + i,
                protocol: Protocol::Tcp,
                bytes_in: 100,
                bytes_out: 100,
                process_name: Some("test.exe".to_string()),
                process_pid: Some(1234),
                timestamp: Utc::now(),
            };
            monitor.analyze_network_event(&event);
        }

        assert!(!monitor.get_active_flows().is_empty());
        assert!(monitor.traffic_stats().total_bytes_in > 0);

        monitor.clear();

        assert!(monitor.get_active_flows().is_empty());
        assert_eq!(monitor.detection_count(), 0);
        assert_eq!(monitor.traffic_stats().total_bytes_in, 0);
        assert_eq!(monitor.traffic_stats().total_bytes_out, 0);
        assert!(monitor.port_scan_trackers.is_empty());
    }

    #[test]
    fn test_with_config() {
        let config = NetworkConfig {
            port_scan_threshold: 5,
            connection_threshold: 3,
            large_transfer_threshold: 1000,
            max_flows: 100,
            ..Default::default()
        };
        let monitor = NetworkMonitor::with_config(config);
        assert_eq!(monitor.config.port_scan_threshold, 5);
        assert_eq!(monitor.config.connection_threshold, 3);
        assert_eq!(monitor.config.large_transfer_threshold, 1000);
        assert_eq!(monitor.config.max_flows, 100);
        assert!(monitor.config.enable_flow_tracking);
        assert!(monitor.config.enable_port_scan_detection);
        assert!(monitor.config.enable_protocol_anomaly);
    }

    #[test]
    fn test_traffic_stats_updated() {
        let mut monitor = NetworkMonitor::new();
        let event = make_event("10.0.0.1", "192.168.1.1", 12345, 443, Protocol::Tcp, 500);
        monitor.analyze_network_event(&event);

        let stats = monitor.traffic_stats();
        assert_eq!(stats.total_bytes_out, 500);
        assert_eq!(stats.total_connections, 1);
        assert!(stats.unique_sources.contains("10.0.0.1"));
        assert!(stats.unique_destinations.contains("192.168.1.1"));
    }

    #[test]
    fn test_detect_port_scan_below_threshold_returns_none() {
        let monitor = NetworkMonitor::new();
        let now = Utc::now();
        let source: IpAddr = "10.0.0.100".parse().unwrap();
        let target: IpAddr = "192.168.1.1".parse().unwrap();

        let tracker = PortScanTracker {
            source_ip: source,
            target_ports: (0..10).map(|p| 1000 + p).collect(),
            first_seen: now,
            last_seen: now,
            unique_targets: HashSet::from([target]),
        };

        let detection = NetworkMonitor::detect_port_scan(&tracker, monitor.config.port_scan_threshold);
        assert!(detection.is_none());
    }

    #[test]
    fn test_detect_large_transfer_below_threshold_returns_none() {
        let monitor = NetworkMonitor::new();
        let event = NetworkEvent {
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("192.168.1.1".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            protocol: Protocol::Tcp,
            bytes_in: 100,
            bytes_out: 50000,
            process_name: Some("test.exe".to_string()),
            process_pid: Some(1234),
            timestamp: Utc::now(),
        };

        let detection = monitor.detect_large_transfer(&event);
        assert!(detection.is_none());
    }
}
