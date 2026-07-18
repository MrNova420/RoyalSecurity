pub mod prelude;

use royalsecurity_common::types::{DnsEvent, EventSeverity, NetworkEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    pub min_connections: u32,
    pub time_window_secs: u64,
    pub jitter_threshold: f64,
    pub regularity_threshold: f64,
    pub dns_query_threshold: u32,
    pub dns_entropy_threshold: f64,
    pub enable_network_beacon: bool,
    pub enable_dns_beacon: bool,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            min_connections: 10,
            time_window_secs: 300,
            jitter_threshold: 0.3,
            regularity_threshold: 0.8,
            dns_query_threshold: 20,
            dns_entropy_threshold: 3.5,
            enable_network_beacon: true,
            enable_dns_beacon: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionWindow {
    pub destination: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub connections: Vec<ConnectionRecord>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub timestamp: DateTime<Utc>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTracker {
    pub domain: String,
    pub queries: Vec<DnsQueryRecord>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryRecord {
    pub query: String,
    pub timestamp: DateTime<Utc>,
    pub subdomain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BeaconType {
    RegularBeacon,
    JitterBeacon,
    DnsBeacon,
    DnsTunnel,
    DeadDrop,
    DomainFronting,
    EncryptedChannel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconAlert {
    pub id: Uuid,
    pub beacon_type: BeaconType,
    pub destination: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub interval_mean_secs: f64,
    pub interval_std_dev: f64,
    pub jitter: f64,
    pub connection_count: u32,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntervalStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub jitter: f64,
    pub regularity: f64,
}

pub struct BeaconDetector {
    connection_windows: HashMap<String, ConnectionWindow>,
    beacons: Vec<BeaconAlert>,
    dns_trackers: HashMap<String, DnsTracker>,
    config: BeaconConfig,
    detection_count: u64,
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self {
            connection_windows: HashMap::new(),
            beacons: Vec::new(),
            dns_trackers: HashMap::new(),
            config: BeaconConfig::default(),
            detection_count: 0,
        }
    }

    pub fn with_config(config: BeaconConfig) -> Self {
        info!(
            "BeaconDetector initialized with config: min_connections={}, time_window={}s, jitter_threshold={}",
            config.min_connections, config.time_window_secs, config.jitter_threshold
        );
        Self {
            connection_windows: HashMap::new(),
            beacons: Vec::new(),
            dns_trackers: HashMap::new(),
            config,
            detection_count: 0,
        }
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn clear(&mut self) {
        self.connection_windows.clear();
        self.beacons.clear();
        self.dns_trackers.clear();
        self.detection_count = 0;
    }

    pub fn analyze_network_event(&mut self, event: &NetworkEvent) -> Vec<BeaconAlert> {
        if !self.config.enable_network_beacon {
            return Vec::new();
        }

        let dst_ip = match event.dst_ip {
            Some(ip) => ip.to_string(),
            None => return Vec::new(),
        };
        let key = format!("{}:{}", dst_ip, event.dst_port);
        let now = event.timestamp;
        let mut alerts = Vec::new();

        let entry = self.connection_windows.entry(key.clone()).or_insert_with(|| {
            debug!("New connection window for destination {}", key);
            ConnectionWindow {
                destination: key.clone(),
                process_name: event.process_name.clone(),
                process_pid: event.process_pid,
                connections: Vec::new(),
                first_seen: now,
                last_seen: now,
                total_bytes_in: 0,
                total_bytes_out: 0,
            }
        });

        entry.connections.push(ConnectionRecord {
            timestamp: now,
            bytes_in: event.bytes_in,
            bytes_out: event.bytes_out,
        });
        entry.last_seen = now;
        entry.total_bytes_in += event.bytes_in;
        entry.total_bytes_out += event.bytes_out;

        if entry.connections.len() as u32 >= self.config.min_connections {
            let window_duration = (now - entry.first_seen).num_seconds() as u64;
            if window_duration >= self.config.time_window_secs {
                let stats = Self::calculate_interval_stats(&entry.connections);
                debug!(
                    "Interval stats for {}: mean={:.2}, std_dev={:.2}, jitter={:.4}, regularity={:.4}",
                    key, stats.mean, stats.std_dev, stats.jitter, stats.regularity
                );

                if stats.mean > 0.0 {
                    if stats.jitter < self.config.jitter_threshold
                        && stats.regularity > self.config.regularity_threshold
                    {
                        let total_payload: u64 = entry
                            .connections
                            .iter()
                            .map(|c| c.bytes_in + c.bytes_out)
                            .sum();
                        let avg_payload = total_payload as f64 / entry.connections.len() as f64;

                        if avg_payload < 512.0 && avg_payload > 10.0 {
                            let alert = BeaconAlert {
                                id: Uuid::new_v4(),
                                beacon_type: BeaconType::DeadDrop,
                                destination: key.clone(),
                                process_name: entry.process_name.clone(),
                                process_pid: entry.process_pid,
                                severity: EventSeverity::High,
                                confidence: 0.85,
                                interval_mean_secs: stats.mean,
                                interval_std_dev: stats.std_dev,
                                jitter: stats.jitter,
                                connection_count: entry.connections.len() as u32,
                                description: format!(
                                    "Dead drop beacon detected to {} with highly regular small payloads (~{:.0} bytes avg)",
                                    key, avg_payload
                                ),
                                evidence: vec![
                                    format!("Mean interval: {:.2}s", stats.mean),
                                    format!("Jitter: {:.4}", stats.jitter),
                                    format!("Avg payload: {:.0} bytes", avg_payload),
                                    format!("Connections: {}", entry.connections.len()),
                                ],
                                timestamp: Utc::now(),
                            };
                            warn!(
                                "Dead drop beacon detected: {} (confidence: {:.2})",
                                key, alert.confidence
                            );
                            self.detection_count += 1;
                            alerts.push(alert);
                        } else {
                            let alert = BeaconAlert {
                                id: Uuid::new_v4(),
                                beacon_type: BeaconType::RegularBeacon,
                                destination: key.clone(),
                                process_name: entry.process_name.clone(),
                                process_pid: entry.process_pid,
                                severity: EventSeverity::High,
                                confidence: 0.9,
                                interval_mean_secs: stats.mean,
                                interval_std_dev: stats.std_dev,
                                jitter: stats.jitter,
                                connection_count: entry.connections.len() as u32,
                                description: format!(
                                    "Regular C2 beacon detected to {} with {:.2}s interval (jitter: {:.4})",
                                    key, stats.mean, stats.jitter
                                ),
                                evidence: vec![
                                    format!("Mean interval: {:.2}s", stats.mean),
                                    format!("Std deviation: {:.4}s", stats.std_dev),
                                    format!("Jitter: {:.4}", stats.jitter),
                                    format!("Regularity: {:.4}", stats.regularity),
                                    format!("Connections: {}", entry.connections.len()),
                                ],
                                timestamp: Utc::now(),
                            };
                            warn!(
                                "Regular beacon detected: {} (confidence: {:.2})",
                                key, alert.confidence
                            );
                            self.detection_count += 1;
                            alerts.push(alert);
                        }
                    } else if stats.jitter >= 0.1 && stats.jitter <= 0.6 && stats.regularity > 0.5 {
                        let alert = BeaconAlert {
                            id: Uuid::new_v4(),
                            beacon_type: BeaconType::JitterBeacon,
                            destination: key.clone(),
                            process_name: entry.process_name.clone(),
                            process_pid: entry.process_pid,
                            severity: EventSeverity::Medium,
                            confidence: 0.75,
                            interval_mean_secs: stats.mean,
                            interval_std_dev: stats.std_dev,
                            jitter: stats.jitter,
                            connection_count: entry.connections.len() as u32,
                            description: format!(
                                "Jitter beacon detected to {} with {:.2}s mean interval (jitter: {:.4})",
                                key, stats.mean, stats.jitter
                            ),
                            evidence: vec![
                                format!("Mean interval: {:.2}s", stats.mean),
                                format!("Jitter: {:.4}", stats.jitter),
                                format!("Regularity: {:.4}", stats.regularity),
                                format!("Connections: {}", entry.connections.len()),
                            ],
                            timestamp: Utc::now(),
                        };
                        warn!(
                            "Jitter beacon detected: {} (confidence: {:.2})",
                            key, alert.confidence
                        );
                        self.detection_count += 1;
                        alerts.push(alert);
                    }
                }
            }
        }

        alerts
    }

    pub fn analyze_dns_event(&mut self, event: &DnsEvent) -> Vec<BeaconAlert> {
        if !self.config.enable_dns_beacon {
            return Vec::new();
        }

        let domain = Self::extract_root_domain(&event.query);
        let subdomain = Self::extract_subdomain(&event.query);
        let now = event.timestamp;
        let mut alerts = Vec::new();

        let tracker = self.dns_trackers.entry(domain.clone()).or_insert_with(|| {
            debug!("New DNS tracker for domain {}", domain);
            DnsTracker {
                domain: domain.clone(),
                queries: Vec::new(),
                first_seen: now,
                last_seen: now,
            }
        });

        tracker.queries.push(DnsQueryRecord {
            query: event.query.clone(),
            timestamp: now,
            subdomain: subdomain.clone(),
        });
        tracker.last_seen = now;

        if tracker.queries.len() as u32 >= self.config.dns_query_threshold {
            if Self::is_dns_tunnel_candidate(tracker) {
                let unique_subdomains: Vec<&str> = tracker
                    .queries
                    .iter()
                    .map(|q| q.subdomain.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();
                let avg_entropy: f64 = tracker
                    .queries
                    .iter()
                    .map(|q| Self::calculate_subdomain_entropy(&q.subdomain))
                    .sum::<f64>()
                    / tracker.queries.len() as f64;

                let alert = BeaconAlert {
                    id: Uuid::new_v4(),
                    beacon_type: BeaconType::DnsTunnel,
                    destination: domain.clone(),
                    process_name: None,
                    process_pid: None,
                    severity: EventSeverity::Critical,
                    confidence: 0.88,
                    interval_mean_secs: 0.0,
                    interval_std_dev: 0.0,
                    jitter: 0.0,
                    connection_count: tracker.queries.len() as u32,
                    description: format!(
                        "DNS tunnel detected on {} with {} unique subdomains (avg entropy: {:.2})",
                        domain,
                        unique_subdomains.len(),
                        avg_entropy
                    ),
                    evidence: vec![
                        format!("Unique subdomains: {}", unique_subdomains.len()),
                        format!("Total queries: {}", tracker.queries.len()),
                        format!("Average entropy: {:.2}", avg_entropy),
                        format!(
                            "Time span: {:.0}s",
                            (tracker.last_seen - tracker.first_seen).num_seconds()
                        ),
                    ],
                    timestamp: Utc::now(),
                };
                warn!(
                    "DNS tunnel detected: {} (confidence: {:.2})",
                    domain, alert.confidence
                );
                self.detection_count += 1;
                alerts.push(alert);
            } else {
                let query_interval_stats =
                    Self::calculate_dns_interval_stats(&tracker.queries);
                if query_interval_stats.mean > 0.0
                    && query_interval_stats.jitter < self.config.jitter_threshold
                    && query_interval_stats.regularity > self.config.regularity_threshold
                {
                    let suspicious_types: Vec<String> = tracker
                        .queries
                        .iter()
                        .map(|_| event.query_type.clone())
                        .filter(|qt| {
                            matches!(
                                qt.as_str(),
                                "TXT" | "NULL" | "CNAME" | "MX" | "SRV" | "ANY"
                            )
                        })
                        .collect();

                    let severity = if !suspicious_types.is_empty() {
                        EventSeverity::High
                    } else {
                        EventSeverity::Medium
                    };

                    let alert = BeaconAlert {
                        id: Uuid::new_v4(),
                        beacon_type: BeaconType::DnsBeacon,
                        destination: domain.clone(),
                        process_name: None,
                        process_pid: None,
                        severity,
                        confidence: 0.72,
                        interval_mean_secs: query_interval_stats.mean,
                        interval_std_dev: query_interval_stats.std_dev,
                        jitter: query_interval_stats.jitter,
                        connection_count: tracker.queries.len() as u32,
                        description: format!(
                            "DNS beacon detected for {} with {:.2}s query interval (jitter: {:.4})",
                            domain, query_interval_stats.mean, query_interval_stats.jitter
                        ),
                        evidence: vec![
                            format!("Mean interval: {:.2}s", query_interval_stats.mean),
                            format!("Jitter: {:.4}", query_interval_stats.jitter),
                            format!("Regularity: {:.4}", query_interval_stats.regularity),
                            format!("Total queries: {}", tracker.queries.len()),
                        ],
                        timestamp: Utc::now(),
                    };
                    warn!(
                        "DNS beacon detected: {} (confidence: {:.2})",
                        domain, alert.confidence
                    );
                    self.detection_count += 1;
                    alerts.push(alert);
                }
            }
        }

        alerts
    }

    pub fn calculate_interval_stats(connections: &[ConnectionRecord]) -> IntervalStats {
        if connections.len() < 2 {
            return IntervalStats {
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                jitter: 0.0,
                regularity: 0.0,
            };
        }

        let mut sorted = connections.to_vec();
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..sorted.len() {
            let diff = sorted[i].timestamp - sorted[i - 1].timestamp;
            intervals.push(diff.num_milliseconds() as f64 / 1000.0);
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let min = intervals.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = intervals
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        let jitter = if mean > 0.0 {
            std_dev / mean
        } else {
            0.0
        };

        let regularity = (1.0 - if mean > 0.0 { std_dev / mean } else { 0.0 }).clamp(0.0, 1.0);

        IntervalStats {
            mean,
            std_dev,
            min,
            max,
            jitter,
            regularity,
        }
    }

    pub fn calculate_subdomain_entropy(subdomain: &str) -> f64 {
        if subdomain.is_empty() {
            return 0.0;
        }

        let len = subdomain.len() as f64;
        let mut freq: HashMap<char, f64> = HashMap::new();

        for c in subdomain.chars() {
            *freq.entry(c).or_insert(0.0) += 1.0;
        }

        let mut entropy = 0.0;
        for &count in freq.values() {
            let p = count / len;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    pub fn is_dns_tunnel_candidate(tracker: &DnsTracker) -> bool {
        if tracker.queries.is_empty() {
            return false;
        }

        let unique_subdomains: std::collections::HashSet<&str> = tracker
            .queries
            .iter()
            .map(|q| q.subdomain.as_str())
            .collect();

        let unique_count = unique_subdomains.len() as u32;
        if unique_count < 10 {
            return false;
        }

        let avg_entropy: f64 = tracker
            .queries
            .iter()
            .map(|q| Self::calculate_subdomain_entropy(&q.subdomain))
            .sum::<f64>()
            / tracker.queries.len() as f64;

        let query_count = tracker.queries.len() as u32;

        unique_count >= 10
            && avg_entropy > 3.0
            && query_count >= 20
    }

    fn extract_root_domain(query: &str) -> String {
        let clean = query.trim_end_matches('.').to_lowercase();
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() >= 2 {
            let len = parts.len();
            format!("{}.{}", parts[len - 2], parts[len - 1])
        } else {
            clean
        }
    }

    fn extract_subdomain(query: &str) -> String {
        let clean = query.trim_end_matches('.').to_lowercase();
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() > 2 {
            parts[..parts.len() - 2].join(".")
        } else {
            String::new()
        }
    }

    fn calculate_dns_interval_stats(queries: &[DnsQueryRecord]) -> IntervalStats {
        if queries.len() < 2 {
            return IntervalStats {
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                jitter: 0.0,
                regularity: 0.0,
            };
        }

        let mut sorted = queries.to_vec();
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..sorted.len() {
            let diff = sorted[i].timestamp - sorted[i - 1].timestamp;
            intervals.push(diff.num_milliseconds() as f64 / 1000.0);
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let min = intervals.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = intervals
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        let jitter = if mean > 0.0 {
            std_dev / mean
        } else {
            0.0
        };
        let regularity = (1.0 - jitter).clamp(0.0, 1.0);

        IntervalStats {
            mean,
            std_dev,
            min,
            max,
            jitter,
            regularity,
        }
    }
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use royalsecurity_common::types::Protocol;
    use std::net::IpAddr;

    fn make_network_event(dst: &str, port: u16, ts: DateTime<Utc>, bytes_in: u64, bytes_out: u64) -> NetworkEvent {
        NetworkEvent {
            src_ip: Some("192.168.1.100".parse::<IpAddr>().unwrap()),
            dst_ip: Some(dst.parse::<IpAddr>().unwrap()),
            src_port: 43210,
            dst_port: port,
            protocol: Protocol::Tcp,
            bytes_in,
            bytes_out,
            process_name: Some("beacon.exe".to_string()),
            process_pid: Some(1234),
            timestamp: ts,
        }
    }

    fn make_dns_event(query: &str, ts: DateTime<Utc>) -> DnsEvent {
        DnsEvent {
            query: query.to_string(),
            query_type: "A".to_string(),
            response: None,
            response_code: Some("NOERROR".to_string()),
            timestamp: ts,
        }
    }

    fn high_entropy_subdomain(seed: u64) -> String {
        let charset = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut result = String::new();
        let mut val = seed;
        for _ in 0..20 {
            val = val.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = (val >> 33) as usize % charset.len();
            result.push(charset[idx] as char);
        }
        result
    }

    #[test]
    fn test_beacon_detector_new() {
        let detector = BeaconDetector::new();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.connection_windows.is_empty());
        assert!(detector.beacons.is_empty());
        assert!(detector.dns_trackers.is_empty());
        assert_eq!(detector.config.min_connections, 10);
        assert_eq!(detector.config.time_window_secs, 300);
        assert!((detector.config.jitter_threshold - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_analyze_network_event_detects_regular_beacon() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();
        let interval = TimeDelta::seconds(60);

        for i in 0..12 {
            let ts = base + interval * i;
            let alerts = detector.analyze_network_event(&make_network_event("10.0.0.1", 443, ts, 1024, 512));
            if i >= 10 {
                assert!(
                    !alerts.is_empty(),
                    "Should detect regular beacon at iteration {}",
                    i
                );
                assert_eq!(alerts[0].beacon_type, BeaconType::RegularBeacon);
                assert_eq!(alerts[0].severity, EventSeverity::High);
                assert!(alerts[0].confidence > 0.8);
                assert!(alerts[0].jitter < 0.3);
            }
        }
        assert!(detector.detection_count() > 0);
    }

    #[test]
    fn test_analyze_network_event_detects_jitter_beacon() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();
        let base_interval = 60;

        for i in 0..15 {
            let jitter_amount = ((i as f64 * 7.3).sin() * 15.0) as i64;
            let ts = base + TimeDelta::seconds(base_interval * i + jitter_amount);
            let alerts = detector.analyze_network_event(&make_network_event("10.0.0.2", 8080, ts, 2048, 1024));
            if i >= 10 {
                let has_jitter = alerts.iter().any(|a| a.beacon_type == BeaconType::JitterBeacon);
                let has_regular = alerts.iter().any(|a| a.beacon_type == BeaconType::RegularBeacon);
                assert!(
                    has_jitter || has_regular,
                    "Should detect either jitter or regular beacon at iteration {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_calculate_interval_stats_regular_data() {
        let base = Utc::now();
        let connections: Vec<ConnectionRecord> = (0..10)
            .map(|i| ConnectionRecord {
                timestamp: base + TimeDelta::seconds(60 * i),
                bytes_in: 100,
                bytes_out: 50,
            })
            .collect();

        let stats = BeaconDetector::calculate_interval_stats(&connections);
        assert!((stats.mean - 60.0).abs() < 0.001);
        assert!((stats.std_dev).abs() < 0.001);
        assert!((stats.min - 60.0).abs() < 0.001);
        assert!((stats.max - 60.0).abs() < 0.001);
        assert!((stats.jitter).abs() < 0.001);
        assert!((stats.regularity - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_interval_stats_irregular_data() {
        let base = Utc::now();
        let intervals = [10_i64, 120, 5, 200, 30, 180, 15, 90, 250, 8];
        let mut connections = Vec::new();
        let mut current = base;
        for &delta in &intervals {
            connections.push(ConnectionRecord {
                timestamp: current,
                bytes_in: 100,
                bytes_out: 50,
            });
            current = current + TimeDelta::seconds(delta);
        }

        let stats = BeaconDetector::calculate_interval_stats(&connections);
        assert!(stats.mean > 0.0);
        assert!(stats.std_dev > 0.0);
        assert!(stats.jitter > 0.3, "Irregular data should have high jitter");
        assert!(stats.regularity < 0.8, "Irregular data should have low regularity");
    }

    #[test]
    fn test_analyze_dns_event_detects_dns_tunnel() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();

        for i in 0..25u64 {
            let subdomain = high_entropy_subdomain(i);
            let query = format!("{}.malicious-c2.example.com", subdomain);
            let ts = base + TimeDelta::seconds(10 * i as i64);
            let alerts = detector.analyze_dns_event(&make_dns_event(&query, ts));
            if i >= 19 {
                let has_tunnel = alerts.iter().any(|a| a.beacon_type == BeaconType::DnsTunnel);
                assert!(
                    has_tunnel,
                    "Should detect DNS tunnel at iteration {}",
                    i
                );
                assert_eq!(alerts.iter().find(|a| a.beacon_type == BeaconType::DnsTunnel).unwrap().severity, EventSeverity::Critical);
            }
        }
    }

    #[test]
    fn test_calculate_subdomain_entropy() {
        assert_eq!(BeaconDetector::calculate_subdomain_entropy(""), 0.0);
        assert!((BeaconDetector::calculate_subdomain_entropy("a") - 0.0).abs() < 0.001);
        let low_entropy = BeaconDetector::calculate_subdomain_entropy("aaaaaaaaaa");
        assert!(low_entropy < 1.0, "Repeated chars should have low entropy");
        let high_entropy = BeaconDetector::calculate_subdomain_entropy("a3F8k2x9Bq");
        assert!(high_entropy > 2.5, "Random-looking string should have high entropy");
        let hex_entropy = BeaconDetector::calculate_subdomain_entropy("4a6f686e");
        assert!(hex_entropy > 1.5, "Hex encoded data should have moderate entropy");
    }

    #[test]
    fn test_is_dns_tunnel_candidate() {
        let base = Utc::now();

        let mut tracker_high_entropy = DnsTracker {
            domain: "c2.example.com".to_string(),
            queries: Vec::new(),
            first_seen: base,
            last_seen: base,
        };
        for i in 0..25u64 {
            let subdomain = high_entropy_subdomain(i);
            tracker_high_entropy.queries.push(DnsQueryRecord {
                query: format!("{}.c2.example.com", subdomain),
                timestamp: base + TimeDelta::seconds(10 * i as i64),
                subdomain,
            });
        }
        assert!(BeaconDetector::is_dns_tunnel_candidate(&tracker_high_entropy));

        let mut tracker_low_entropy = DnsTracker {
            domain: "normal.com".to_string(),
            queries: Vec::new(),
            first_seen: base,
            last_seen: base,
        };
        for i in 0..25 {
            let subdomain = format!("host{}", i);
            tracker_low_entropy.queries.push(DnsQueryRecord {
                query: format!("{}.normal.com", subdomain),
                timestamp: base + TimeDelta::seconds(300 * i),
                subdomain,
            });
        }
        assert!(!BeaconDetector::is_dns_tunnel_candidate(&tracker_low_entropy));

        let empty_tracker = DnsTracker {
            domain: "empty.com".to_string(),
            queries: Vec::new(),
            first_seen: base,
            last_seen: base,
        };
        assert!(!BeaconDetector::is_dns_tunnel_candidate(&empty_tracker));
    }

    #[test]
    fn test_below_min_connections_does_not_trigger() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();

        for i in 0..5 {
            let ts = base + TimeDelta::seconds(60 * i);
            let alerts = detector.analyze_network_event(&make_network_event("10.0.0.3", 443, ts, 1024, 512));
            assert!(alerts.is_empty(), "Should not trigger with fewer than min_connections");
        }
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn test_detection_count_increments() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();
        let interval = TimeDelta::seconds(60);

        for i in 0..12 {
            let ts = base + interval * i;
            detector.analyze_network_event(&make_network_event("10.0.0.4", 443, ts, 1024, 512));
        }
        let count = detector.detection_count();
        assert!(count >= 1, "Detection count should have incremented, got {}", count);
    }

    #[test]
    fn test_clear_resets_state() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();
        let interval = TimeDelta::seconds(60);

        for i in 0..12 {
            let ts = base + interval * i;
            detector.analyze_network_event(&make_network_event("10.0.0.5", 443, ts, 1024, 512));
        }
        assert!(detector.detection_count() > 0);
        detector.clear();
        assert_eq!(detector.detection_count(), 0);
        assert!(detector.connection_windows.is_empty());
        assert!(detector.beacons.is_empty());
        assert!(detector.dns_trackers.is_empty());
    }

    #[test]
    fn test_with_config() {
        let config = BeaconConfig {
            min_connections: 3,
            time_window_secs: 60,
            jitter_threshold: 0.5,
            regularity_threshold: 0.6,
            ..Default::default()
        };
        let mut detector = BeaconDetector::with_config(config);
        assert_eq!(detector.config.min_connections, 3);
        assert_eq!(detector.config.time_window_secs, 60);

        let base = Utc::now();
        for i in 0..5 {
            let ts = base + TimeDelta::seconds(20 * i);
            let alerts = detector.analyze_network_event(&make_network_event("10.0.0.6", 443, ts, 1024, 512));
            if i >= 3 {
                assert!(!alerts.is_empty(), "Should trigger with lower min_connections at iteration {}", i);
            }
        }
    }

    #[test]
    fn test_dead_drop_detection() {
        let mut detector = BeaconDetector::new();
        let base = Utc::now();
        let interval = TimeDelta::seconds(60);

        for i in 0..15 {
            let ts = base + interval * i;
            let alerts = detector.analyze_network_event(&make_network_event("10.0.0.7", 443, ts, 100, 50));
            if i >= 10 {
                let has_dead_drop = alerts.iter().any(|a| a.beacon_type == BeaconType::DeadDrop);
                assert!(
                    has_dead_drop,
                    "Should detect dead drop at iteration {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_extract_root_domain() {
        assert_eq!(BeaconDetector::extract_root_domain("sub.example.com."), "example.com");
        assert_eq!(BeaconDetector::extract_root_domain("deep.sub.example.com"), "example.com");
        assert_eq!(BeaconDetector::extract_root_domain("single.com"), "single.com");
    }

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(BeaconDetector::extract_subdomain("sub.example.com"), "sub");
        assert_eq!(BeaconDetector::extract_subdomain("deep.sub.example.com"), "deep.sub");
        assert_eq!(BeaconDetector::extract_subdomain("example.com"), "");
    }

    #[test]
    fn test_disable_network_beacon() {
        let config = BeaconConfig {
            enable_network_beacon: false,
            ..Default::default()
        };
        let mut detector = BeaconDetector::with_config(config);
        let base = Utc::now();
        let interval = TimeDelta::seconds(60);

        for i in 0..15 {
            let ts = base + interval * i;
            let alerts = detector.analyze_network_event(&make_network_event("10.0.0.8", 443, ts, 1024, 512));
            assert!(alerts.is_empty(), "Should not detect when network beacon is disabled");
        }
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn test_disable_dns_beacon() {
        let config = BeaconConfig {
            enable_dns_beacon: false,
            ..Default::default()
        };
        let mut detector = BeaconDetector::with_config(config);
        let base = Utc::now();

        for i in 0..25u64 {
            let subdomain = high_entropy_subdomain(i);
            let query = format!("{}.c2.example.com", subdomain);
            let ts = base + TimeDelta::seconds(10 * i as i64);
            let alerts = detector.analyze_dns_event(&make_dns_event(&query, ts));
            assert!(alerts.is_empty(), "Should not detect when DNS beacon is disabled");
        }
        assert_eq!(detector.detection_count(), 0);
    }
}
