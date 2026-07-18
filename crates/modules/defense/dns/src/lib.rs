pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{DnsEvent, EventSeverity};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};
use uuid::Uuid;

const KNOWN_BRANDS: &[&str] = &[
    "google",
    "facebook",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "twitter",
    "linkedin",
    "github",
    "netflix",
];

const COMMON_TLDS: &[&str] = &[
    "com", "net", "org", "info", "biz", "ru", "cn", "tk",
];

const SINKHOLE_IPS: &[&str] = &["0.0.0.0", "127.0.0.1", "127.0.0.2", "::1"];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsThreatType {
    C2Domain,
    DnsTunnel,
    DgaDomain,
    Typosquatting,
    Sinkhole,
    MalwareDomain,
    PhishingDomain,
    CryptominingPool,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub enable_blocking: bool,
    pub enable_tunnel_detection: bool,
    pub enable_typosquatting: bool,
    pub max_query_log: usize,
    pub tunnel_entropy_threshold: f64,
    pub tunnel_length_threshold: usize,
    pub max_cname_chain: u32,
    pub suspicious_types: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable_blocking: true,
            enable_tunnel_detection: true,
            enable_typosquatting: true,
            max_query_log: 10000,
            tunnel_entropy_threshold: 3.5,
            tunnel_length_threshold: 50,
            max_cname_chain: 5,
            suspicious_types: vec![
                "NULL".to_string(),
                "ANY".to_string(),
                "TXT".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub ip_addresses: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub query_count: u32,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DnsQueryLog {
    pub query: String,
    pub query_type: String,
    pub response: Option<String>,
    pub process_name: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DnsDetection {
    pub id: Uuid,
    pub threat_type: DnsThreatType,
    pub domain: String,
    pub severity: EventSeverity,
    pub confidence: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub blocked: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TyposquattingResult {
    pub query_domain: String,
    pub target_domain: String,
    pub edit_distance: u32,
    pub similarity_score: f64,
    pub technique: String,
}

pub struct DnsMonitor {
    pub blocklist: HashSet<String>,
    pub allowlist: HashSet<String>,
    pub dns_cache: HashMap<String, DnsCacheEntry>,
    pub query_log: Vec<DnsQueryLog>,
    pub detections: Vec<DnsDetection>,
    pub config: DnsConfig,
    pub detection_count: u64,
}

impl Default for DnsMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsMonitor {
    pub fn new() -> Self {
        Self {
            blocklist: HashSet::new(),
            allowlist: HashSet::new(),
            dns_cache: HashMap::new(),
            query_log: Vec::new(),
            detections: Vec::new(),
            config: DnsConfig::default(),
            detection_count: 0,
        }
    }

    pub fn with_config(config: DnsConfig) -> Self {
        Self {
            blocklist: HashSet::new(),
            allowlist: HashSet::new(),
            dns_cache: HashMap::new(),
            query_log: Vec::new(),
            detections: Vec::new(),
            config,
            detection_count: 0,
        }
    }

    pub fn analyze_dns_event(
        &mut self,
        event: &DnsEvent,
        process_pid: Option<u32>,
        process_name: Option<&str>,
    ) -> Vec<DnsDetection> {
        let mut detections = Vec::new();
        let domain = extract_base_domain(&event.query);

        if self.is_allowed(&domain) {
            debug!("Domain {} is in allowlist, skipping analysis", domain);
            return detections;
        }

        if self.is_blocked(&domain) {
            warn!("Blocked domain detected: {}", domain);
            let detection = DnsDetection {
                id: Uuid::new_v4(),
                threat_type: DnsThreatType::C2Domain,
                domain: domain.clone(),
                severity: EventSeverity::High,
                confidence: 1.0,
                description: format!("Domain {} is in the blocklist", domain),
                evidence: vec![event.query.clone()],
                process_name: process_name.map(String::from),
                process_pid,
                blocked: self.config.enable_blocking,
                timestamp: Utc::now(),
            };
            self.detection_count += 1;
            detections.push(detection);
        }

        if self.config.enable_tunnel_detection {
            if let Some(detection) = self.detect_dns_tunnel(event) {
                warn!(
                    "DNS tunnel detected for domain {}: {}",
                    domain, detection.description
                );
                detections.push(detection);
            }
        }

        if self.config.enable_typosquatting {
            let typos = self.detect_typosquatting(&domain);
            for typo in typos {
                warn!(
                    "Typosquatting detected: {} -> {} ({})",
                    typo.query_domain, typo.target_domain, typo.technique
                );
                let detection = DnsDetection {
                    id: Uuid::new_v4(),
                    threat_type: DnsThreatType::Typosquatting,
                    domain: domain.clone(),
                    severity: EventSeverity::Medium,
                    confidence: typo.similarity_score as f32,
                    description: format!(
                        "Domain {} is likely typosquatting of {} (technique: {})",
                        typo.query_domain, typo.target_domain, typo.technique
                    ),
                    evidence: vec![
                        format!("edit_distance={}", typo.edit_distance),
                        format!("similarity={:.4}", typo.similarity_score),
                        format!("technique={}", typo.technique),
                    ],
                    process_name: process_name.map(String::from),
                    process_pid,
                    blocked: false,
                    timestamp: Utc::now(),
                };
                self.detection_count += 1;
                detections.push(detection);
            }
        }

        if let Some(response) = &event.response {
            if SINKHOLE_IPS.contains(&response.as_str()) {
                warn!("Sinkhole response detected for domain {}: {}", domain, response);
                let detection = DnsDetection {
                    id: Uuid::new_v4(),
                    threat_type: DnsThreatType::Sinkhole,
                    domain: domain.clone(),
                    severity: EventSeverity::Informational,
                    confidence: 0.9,
                    description: format!(
                        "Domain {} resolved to sinkhole IP {}",
                        domain, response
                    ),
                    evidence: vec![format!("response={}", response)],
                    process_name: process_name.map(String::from),
                    process_pid,
                    blocked: false,
                    timestamp: Utc::now(),
                };
                self.detection_count += 1;
                detections.push(detection);
            }
        }

        self.log_query(
            &event.query,
            &event.query_type,
            event.response.as_deref(),
            process_name,
        );

        self.update_cache(&domain, event.response.as_deref());

        if !detections.is_empty() {
            for d in &detections {
                self.detections.push(d.clone());
            }
        }

        detections
    }

    pub fn detect_dns_tunnel(&self, event: &DnsEvent) -> Option<DnsDetection> {
        let subdomain = extract_subdomain(&event.query);

        let mut reasons = Vec::new();
        let mut total_confidence: f32 = 0.0;
        let mut count: u32 = 0;

        if !subdomain.is_empty() {
            let entropy = calculate_subdomain_entropy(&event.query);
            if entropy > self.config.tunnel_entropy_threshold {
                reasons.push(format!(
                    "High entropy subdomain: {:.2} (threshold: {:.2})",
                    entropy, self.config.tunnel_entropy_threshold
                ));
                total_confidence += 0.4;
                count += 1;
            }

            if subdomain.len() > self.config.tunnel_length_threshold {
                reasons.push(format!(
                    "Subdomain length {} exceeds threshold {}",
                    subdomain.len(),
                    self.config.tunnel_length_threshold
                ));
                total_confidence += 0.3;
                count += 1;
            }
        }

        if self.config.suspicious_types.contains(&event.query_type) {
            reasons.push(format!(
                "Suspicious query type: {}",
                event.query_type
            ));
            total_confidence += 0.2;
            count += 1;
        }

        if count == 0 {
            return None;
        }

        let confidence = (total_confidence / count as f32).min(1.0);
        let severity = if confidence > 0.8 {
            EventSeverity::High
        } else if confidence > 0.5 {
            EventSeverity::Medium
        } else {
            EventSeverity::Low
        };

        Some(DnsDetection {
            id: Uuid::new_v4(),
            threat_type: DnsThreatType::DnsTunnel,
            domain: event.query.clone(),
            severity,
            confidence,
            description: format!(
                "Possible DNS tunneling detected: {} indicators found",
                count
            ),
            evidence: reasons,
            process_name: None,
            process_pid: None,
            blocked: self.config.enable_blocking,
            timestamp: Utc::now(),
        })
    }

    pub fn detect_typosquatting(&self, domain: &str) -> Vec<TyposquattingResult> {
        let mut results = Vec::new();
        let base = strip_tld(domain);

        if base.is_empty() {
            return results;
        }

        for &brand in KNOWN_BRANDS {
            let brand_base = brand.to_lowercase();
            let base_lower = base.to_lowercase();

            if base_lower == brand_base {
                continue;
            }

            let edit_distance = calculate_levenshtein(&base_lower, &brand_base);
            let max_len = base_lower.len().max(brand_base.len()) as f64;
            let similarity_score = if max_len > 0.0 {
                1.0 - (edit_distance as f64 / max_len)
            } else {
                0.0
            };

            if edit_distance == 0 || edit_distance > 3 {
                continue;
            }

            let technique = if edit_distance == 1 && base_lower.len() == brand_base.len() {
                detect_swap_technique(&base_lower, &brand_base)
            } else if has_homograph(&base_lower, &brand_base) {
                "homograph".to_string()
            } else if base_lower.len() == brand_base.len() {
                "bit_squatting".to_string()
            } else {
                "character_substitution".to_string()
            };

            results.push(TyposquattingResult {
                query_domain: domain.to_string(),
                target_domain: format!("{}.{}", brand, COMMON_TLDS[0]),
                edit_distance,
                similarity_score,
                technique,
            });
        }

        results
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.blocklist.iter().any(|b| {
            let bl = b.trim_end_matches('.').to_lowercase();
            domain_lower == bl || domain_lower.ends_with(&format!(".{}", bl))
        })
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        if self.allowlist.is_empty() {
            return false;
        }
        let domain_lower = domain.trim_end_matches('.').to_lowercase();
        self.allowlist.iter().any(|a| {
            let al = a.trim_end_matches('.').to_lowercase();
            domain_lower == al || domain_lower.ends_with(&format!(".{}", al))
        })
    }

    pub fn add_to_blocklist(&mut self, domain: String) {
        info!("Adding domain to blocklist: {}", domain);
        self.blocklist.insert(domain);
    }

    pub fn remove_from_blocklist(&mut self, domain: &str) {
        info!("Removing domain from blocklist: {}", domain);
        self.blocklist.remove(domain);
    }

    pub fn add_to_allowlist(&mut self, domain: String) {
        info!("Adding domain to allowlist: {}", domain);
        self.allowlist.insert(domain);
    }

    pub fn remove_from_allowlist(&mut self, domain: &str) {
        info!("Removing domain from allowlist: {}", domain);
        self.allowlist.remove(domain);
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn clear(&mut self) {
        info!("Clearing DNS monitor state");
        self.dns_cache.clear();
        self.query_log.clear();
        self.detections.clear();
        self.detection_count = 0;
    }

    fn log_query(
        &mut self,
        query: &str,
        query_type: &str,
        response: Option<&str>,
        process_name: Option<&str>,
    ) {
        let log_entry = DnsQueryLog {
            query: query.to_string(),
            query_type: query_type.to_string(),
            response: response.map(String::from),
            process_name: process_name.map(String::from),
            timestamp: Utc::now(),
        };
        self.query_log.push(log_entry);
        if self.query_log.len() > self.config.max_query_log {
            let excess = self.query_log.len() - self.config.max_query_log;
            self.query_log.drain(0..excess);
        }
        debug!("Logged DNS query: {} (type: {})", query, query_type);
    }

    fn update_cache(&mut self, domain: &str, response: Option<&str>) {
        let now = Utc::now();
        if let Some(entry) = self.dns_cache.get_mut(domain) {
            entry.last_seen = now;
            entry.query_count += 1;
            if let Some(ip) = response {
                if !entry.ip_addresses.contains(&ip.to_string()) {
                    entry.ip_addresses.push(ip.to_string());
                }
            }
        } else {
            let entry = DnsCacheEntry {
                domain: domain.to_string(),
                ip_addresses: response.map(|r| vec![r.to_string()]).unwrap_or_default(),
                first_seen: now,
                last_seen: now,
                query_count: 1,
                ttl: None,
            };
            self.dns_cache.insert(domain.to_string(), entry);
        }
    }
}

pub fn calculate_levenshtein(s1: &str, s2: &str) -> u32 {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let len1 = s1_chars.len();
    let len2 = s2_chars.len();

    let mut matrix = vec![vec![0u32; len2 + 1]; len1 + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i as u32;
    }
    for (j, cell) in matrix[0].iter_mut().enumerate().take(len2 + 1) {
        *cell = j as u32;
    }

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[len1][len2]
}

pub fn calculate_subdomain_entropy(domain: &str) -> f64 {
    let subdomain = extract_subdomain(domain);
    if subdomain.is_empty() {
        return 0.0;
    }

    let len = subdomain.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq = HashMap::new();
    for ch in subdomain.chars() {
        *freq.entry(ch).or_insert(0u32) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn extract_base_domain(query: &str) -> String {
    let q = query.trim_end_matches('.');
    let parts: Vec<&str> = q.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        q.to_string()
    }
}

fn extract_subdomain(query: &str) -> String {
    let q = query.trim_end_matches('.');
    let parts: Vec<&str> = q.split('.').collect();
    if parts.len() > 2 {
        parts[..parts.len() - 2].join(".")
    } else {
        String::new()
    }
}

fn strip_tld(domain: &str) -> String {
    let d = domain.trim_end_matches('.');
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2].to_string()
    } else {
        d.to_string()
    }
}

fn detect_swap_technique(s1: &str, s2: &str) -> String {
    let c1: Vec<char> = s1.chars().collect();
    let c2: Vec<char> = s2.chars().collect();
    if c1.len() != c2.len() {
        return "character_substitution".to_string();
    }
    for i in 0..c1.len() {
        if c1[i] != c2[i]
            && i + 1 < c1.len()
            && c1[i] == c2[i + 1]
            && c1[i + 1] == c2[i]
        {
            return "character_swap".to_string();
        }
    }
    "character_substitution".to_string()
}

fn has_homograph(s1: &str, s2: &str) -> bool {
    let c1: Vec<char> = s1.chars().collect();
    let c2: Vec<char> = s2.chars().collect();
    if c1.len() != c2.len() {
        return false;
    }
    let mut diff_count = 0;
    for (a, b) in c1.iter().zip(c2.iter()) {
        if a != b {
            diff_count += 1;
            if *a as u32 >= 0x0400 && *a as u32 <= 0x04FF {
                return true;
            }
            if *b as u32 >= 0x0400 && *b as u32 <= 0x04FF {
                return true;
            }
        }
    }
    diff_count > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dns_event(query: &str, query_type: &str, response: Option<&str>) -> DnsEvent {
        DnsEvent {
            query: query.to_string(),
            query_type: query_type.to_string(),
            response: response.map(String::from),
            response_code: Some("NOERROR".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_dns_monitor_new() {
        let monitor = DnsMonitor::new();
        assert!(monitor.blocklist.is_empty());
        assert!(monitor.allowlist.is_empty());
        assert!(monitor.dns_cache.is_empty());
        assert!(monitor.query_log.is_empty());
        assert!(monitor.detections.is_empty());
        assert_eq!(monitor.detection_count(), 0);
        assert!(monitor.config.enable_blocking);
        assert!(monitor.config.enable_tunnel_detection);
        assert!(monitor.config.enable_typosquatting);
    }

    #[test]
    fn test_analyze_dns_event_blocked_domain() {
        let mut monitor = DnsMonitor::new();
        monitor.add_to_blocklist("evil.com".to_string());
        let event = make_dns_event("sub.evil.com", "A", Some("1.2.3.4"));
        let detections = monitor.analyze_dns_event(&event, Some(1234), Some("malware.exe"));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].threat_type, DnsThreatType::C2Domain);
        assert_eq!(detections[0].severity, EventSeverity::High);
        assert_eq!(detections[0].confidence, 1.0);
        assert_eq!(detections[0].process_name.as_deref(), Some("malware.exe"));
        assert_eq!(detections[0].process_pid, Some(1234));
        assert!(detections[0].blocked);
    }

    #[test]
    fn test_detect_dns_tunnel_high_entropy() {
        let monitor = DnsMonitor::new();
        let event = make_dns_event(
            "aGVsbG93b3JsZGRhdGF0cmFuc2ZlcmluZ3Rlc3Q.evil.com",
            "TXT",
            Some("encoded-data-here"),
        );
        let detection = monitor.detect_dns_tunnel(&event);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.threat_type, DnsThreatType::DnsTunnel);
        assert!(d.confidence > 0.0);
        assert!(!d.evidence.is_empty());
    }

    #[test]
    fn test_detect_dns_tunnel_long_subdomain() {
        let config = DnsConfig {
            tunnel_length_threshold: 20,
            ..DnsConfig::default()
        };
        let monitor = DnsMonitor::with_config(config);
        let long_sub = "a".repeat(30);
        let event = make_dns_event(
            &format!("{}.evil.com", long_sub),
            "A",
            Some("1.2.3.4"),
        );
        let detection = monitor.detect_dns_tunnel(&event);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert!(d.evidence.iter().any(|e| e.contains("Subdomain length")));
    }

    #[test]
    fn test_detect_typosquatting_finds_similar() {
        let monitor = DnsMonitor::new();
        let results = monitor.detect_typosquatting("gogle.com");
        assert!(!results.is_empty());
        let r = &results[0];
        assert_eq!(r.target_domain, "google.com");
        assert!(r.edit_distance >= 1 && r.edit_distance <= 2);
        assert!(r.similarity_score > 0.5);
    }

    #[test]
    fn test_calculate_levenshtein_known_strings() {
        assert_eq!(calculate_levenshtein("", ""), 0);
        assert_eq!(calculate_levenshtein("kitten", "kitten"), 0);
        assert_eq!(calculate_levenshtein("kitten", "sitten"), 1);
        assert_eq!(calculate_levenshtein("kitten", "sitting"), 3);
        assert_eq!(calculate_levenshtein("", "abc"), 3);
        assert_eq!(calculate_levenshtein("abc", ""), 3);
        assert_eq!(calculate_levenshtein("google", "gogle"), 1);
        assert_eq!(calculate_levenshtein("amazon", "amazn"), 1);
    }

    #[test]
    fn test_calculate_subdomain_entropy() {
        let low_entropy = calculate_subdomain_entropy("ababab.evil.com");
        let high_entropy = calculate_subdomain_entropy("x7k9m2p4.evil.com");
        assert!(low_entropy < high_entropy);

        let empty_entropy = calculate_subdomain_entropy("evil.com");
        assert_eq!(empty_entropy, 0.0);

        let uniform = calculate_subdomain_entropy("abcdefgh.evil.com");
        assert!(uniform > low_entropy);
    }

    #[test]
    fn test_is_blocked_and_is_allowed() {
        let mut monitor = DnsMonitor::new();
        assert!(!monitor.is_blocked("evil.com"));
        monitor.add_to_blocklist("evil.com".to_string());
        assert!(monitor.is_blocked("evil.com"));
        assert!(monitor.is_blocked("sub.evil.com"));

        assert!(!monitor.is_allowed("good.com"));
        monitor.add_to_allowlist("good.com".to_string());
        assert!(monitor.is_allowed("good.com"));
        assert!(monitor.is_allowed("sub.good.com"));
    }

    #[test]
    fn test_add_to_blocklist_and_remove() {
        let mut monitor = DnsMonitor::new();
        monitor.add_to_blocklist("test.com".to_string());
        assert!(monitor.is_blocked("test.com"));
        monitor.remove_from_blocklist("test.com");
        assert!(!monitor.is_blocked("test.com"));
    }

    #[test]
    fn test_typosquatting_character_swap() {
        let monitor = DnsMonitor::new();
        let results = monitor.detect_typosquatting("goolge.com");
        assert!(!results.is_empty());
        let r = results.iter().find(|r| r.target_domain == "google.com");
        assert!(r.is_some());
        let r = r.unwrap();
        assert_eq!(r.edit_distance, 2);
        assert!(r.similarity_score > 0.6);
    }

    #[test]
    fn test_typosquatting_homograph_unicode() {
        let monitor = DnsMonitor::new();
        let results = monitor.detect_typosquatting("g\u{043E}ogle.com");
        assert!(!results.is_empty());
        let has_homograph = results.iter().any(|r| r.technique == "homograph");
        assert!(has_homograph);
    }

    #[test]
    fn test_clear() {
        let mut monitor = DnsMonitor::new();
        monitor.add_to_blocklist("evil.com".to_string());
        monitor.add_to_allowlist("good.com".to_string());
        let event = make_dns_event("test.com", "A", Some("1.2.3.4"));
        monitor.analyze_dns_event(&event, None, None);
        assert!(!monitor.query_log.is_empty());
        assert!(!monitor.dns_cache.is_empty());

        monitor.clear();
        assert!(monitor.dns_cache.is_empty());
        assert!(monitor.query_log.is_empty());
        assert!(monitor.detections.is_empty());
        assert_eq!(monitor.detection_count(), 0);
    }

    #[test]
    fn test_sinkhole_detection() {
        let mut monitor = DnsMonitor::new();
        let event = make_dns_event("malware.com", "A", Some("0.0.0.0"));
        let detections = monitor.analyze_dns_event(&event, None, None);
        let sinkhole = detections
            .iter()
            .find(|d| d.threat_type == DnsThreatType::Sinkhole);
        assert!(sinkhole.is_some());
        let s = sinkhole.unwrap();
        assert_eq!(s.severity, EventSeverity::Informational);
    }

    #[test]
    fn test_detection_count_increments() {
        let mut monitor = DnsMonitor::new();
        monitor.add_to_blocklist("evil.com".to_string());
        assert_eq!(monitor.detection_count(), 0);
        let event1 = make_dns_event("evil.com", "A", Some("1.2.3.4"));
        monitor.analyze_dns_event(&event1, None, None);
        assert!(monitor.detection_count() >= 1);
        let event2 = make_dns_event("other-evil.com", "A", Some("5.6.7.8"));
        monitor.add_to_blocklist("other-evil.com".to_string());
        monitor.analyze_dns_event(&event2, None, None);
        assert!(monitor.detection_count() >= 2);
    }

    #[test]
    fn test_query_log_max_size() {
        let config = DnsConfig {
            max_query_log: 5,
            ..DnsConfig::default()
        };
        let mut monitor = DnsMonitor::with_config(config);
        for i in 0..10 {
            let event = make_dns_event(
                &format!("host{}.example.com", i),
                "A",
                Some("1.2.3.4"),
            );
            monitor.analyze_dns_event(&event, None, None);
        }
        assert!(monitor.query_log.len() <= 5);
    }

    #[test]
    fn test_allowlist_skips_analysis() {
        let mut monitor = DnsMonitor::new();
        monitor.add_to_allowlist("safe.com".to_string());
        monitor.add_to_blocklist("safe.com".to_string());
        let event = make_dns_event("safe.com", "A", Some("1.2.3.4"));
        let detections = monitor.analyze_dns_event(&event, None, None);
        assert!(detections.is_empty());
    }
}
