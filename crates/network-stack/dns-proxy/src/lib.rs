pub mod prelude;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum DnsProxyError {
    #[error("cache full")]
    CacheFull,
    #[error("blocked domain: {0}")]
    Blocked(String),
    #[error("upstream failure: {0}")]
    UpstreamFailure(String),
}

// ---------------------------------------------------------------------------
// DnsRecordType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Soa,
    Srv,
    Caa,
    Https,
}

// ---------------------------------------------------------------------------
// DnsQuery / DnsAnswer / DnsResponse
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub query_type: DnsRecordType,
    pub client_ip: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rdata: String,
    pub ttl: u32,
    pub record_type: DnsRecordType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    pub id: u16,
    pub answers: Vec<DnsAnswer>,
    pub truncated: bool,
    pub authoritative: bool,
}

// ---------------------------------------------------------------------------
// DnsCache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCache {
    pub query: String,
    pub response: DnsAnswer,
    pub ttl: u32,
    pub cached_at: DateTime<Utc>,
    pub hits: u64,
}

// ---------------------------------------------------------------------------
// DnsProxyConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProxyConfig {
    pub listen_addr: SocketAddr,
    pub upstream_servers: Vec<String>,
    pub cache_size: usize,
    pub block_malicious: bool,
    pub enable_doh: bool,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:53".parse().unwrap(),
            upstream_servers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
            ],
            cache_size: 10_000,
            block_malicious: true,
            enable_doh: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DnsStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsStats {
    pub queries_handled: u64,
    pub cached: u64,
    pub blocked: u64,
    pub forwarded: u64,
    pub doh_relayed: u64,
}

// ---------------------------------------------------------------------------
// DnsProxy
// ---------------------------------------------------------------------------

pub struct DnsProxy {
    config: DnsProxyConfig,
    cache: VecDeque<DnsCache>,
    blocklist: HashSet<String>,
    stats: DnsStats,
}

impl DnsProxy {
    pub fn new() -> Self {
        Self::with_config(DnsProxyConfig::default())
    }

    pub fn with_config(config: DnsProxyConfig) -> Self {
        info!(
            listen = %config.listen_addr,
            upstreams = config.upstream_servers.len(),
            cache_size = config.cache_size,
            "Initialized DNS proxy"
        );
        Self {
            config,
            cache: VecDeque::new(),
            blocklist: HashSet::new(),
            stats: DnsStats::default(),
        }
    }

    pub fn handle_query(&mut self, query: &DnsQuery) -> DnsResponse {
        self.stats.queries_handled += 1;

        if self.config.block_malicious && self.is_blocked(&query.name) {
            self.stats.blocked += 1;
            warn!(domain = %query.name, "Blocked malicious DNS query");
            return DnsResponse {
                id: query.id,
                answers: vec![],
                truncated: false,
                authoritative: false,
            };
        }

        if let Some(answer) = self.cache_lookup(&query.name) {
            let answer = answer.clone();
            self.stats.cached += 1;
            debug!(domain = %query.name, "DNS cache hit");
            return DnsResponse {
                id: query.id,
                answers: vec![answer],
                truncated: false,
                authoritative: false,
            };
        }

        self.stats.forwarded += 1;
        if self.config.enable_doh {
            self.stats.doh_relayed += 1;
        }

        debug!(domain = %query.name, "Forwarding DNS query upstream");
        DnsResponse {
            id: query.id,
            answers: vec![],
            truncated: false,
            authoritative: false,
        }
    }

    pub fn cache_lookup(&self, query: &str) -> Option<&DnsAnswer> {
        self.cache
            .iter()
            .find(|c| c.query == query)
            .map(|c| &c.response)
    }

    pub fn cache_insert(&mut self, query: String, answer: DnsAnswer) {
        if self.cache.len() >= self.config.cache_size {
            self.cache.pop_front();
        }
        self.cache.push_back(DnsCache {
            query,
            response: answer,
            ttl: 300,
            cached_at: Utc::now(),
            hits: 0,
        });
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.blocklist.iter().any(|entry| {
            domain_lower == *entry || domain_lower.ends_with(&format!(".{entry}"))
        })
    }

    pub fn add_blocklist_entry(&mut self, domain: String) {
        info!(domain = %domain, "Added blocklist entry");
        self.blocklist.insert(domain);
    }

    pub fn stats(&self) -> &DnsStats {
        &self.stats
    }
}

impl Default for DnsProxy {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(name: &str) -> DnsQuery {
        DnsQuery {
            id: 1,
            name: name.to_string(),
            query_type: DnsRecordType::A,
            client_ip: "127.0.0.1".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_new_proxy() {
        let proxy = DnsProxy::new();
        assert_eq!(proxy.stats.queries_handled, 0);
        assert!(proxy.blocklist.is_empty());
    }

    #[test]
    fn test_with_config() {
        let config = DnsProxyConfig {
            cache_size: 500,
            enable_doh: false,
            ..Default::default()
        };
        let proxy = DnsProxy::with_config(config);
        assert_eq!(proxy.config.cache_size, 500);
        assert!(!proxy.config.enable_doh);
    }

    #[test]
    fn test_handle_query_blocked() {
        let mut proxy = DnsProxy::new();
        proxy.add_blocklist_entry("malware.example".to_string());

        let query = make_query("malware.example");
        let response = proxy.handle_query(&query);

        assert!(response.answers.is_empty());
        assert_eq!(proxy.stats().blocked, 1);
    }

    #[test]
    fn test_handle_query_allowed() {
        let mut proxy = DnsProxy::new();
        let query = make_query("safe.example");
        let response = proxy.handle_query(&query);

        assert_eq!(response.id, 1);
        assert_eq!(proxy.stats().forwarded, 1);
    }

    #[test]
    fn test_cache_lookup_miss() {
        let proxy = DnsProxy::new();
        assert!(proxy.cache_lookup("nonexistent.example").is_none());
    }

    #[test]
    fn test_cache_insert_and_lookup() {
        let mut proxy = DnsProxy::new();
        let answer = DnsAnswer {
            name: "example.com".to_string(),
            rdata: "93.184.216.34".to_string(),
            ttl: 300,
            record_type: DnsRecordType::A,
        };
        proxy.cache_insert("example.com".to_string(), answer.clone());

        let cached = proxy.cache_lookup("example.com");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().rdata, "93.184.216.34");
    }

    #[test]
    fn test_handle_query_cache_hit() {
        let mut proxy = DnsProxy::new();
        let answer = DnsAnswer {
            name: "cached.example".to_string(),
            rdata: "10.0.0.1".to_string(),
            ttl: 300,
            record_type: DnsRecordType::A,
        };
        proxy.cache_insert("cached.example".to_string(), answer);

        let query = make_query("cached.example");
        let response = proxy.handle_query(&query);

        assert_eq!(response.answers.len(), 1);
        assert_eq!(proxy.stats().cached, 1);
    }

    #[test]
    fn test_is_blocked_subdomain() {
        let mut proxy = DnsProxy::new();
        proxy.add_blocklist_entry("evil.com".to_string());

        assert!(proxy.is_blocked("evil.com"));
        assert!(proxy.is_blocked("sub.evil.com"));
        assert!(proxy.is_blocked("SUB.EVIL.COM"));
        assert!(!proxy.is_blocked("good.com"));
    }

    #[test]
    fn test_stats_tracking() {
        let mut proxy = DnsProxy::new();
        proxy.handle_query(&make_query("a.example"));
        proxy.handle_query(&make_query("b.example"));

        let stats = proxy.stats();
        assert_eq!(stats.queries_handled, 2);
        assert_eq!(stats.forwarded, 2);
    }

    #[test]
    fn test_default_config_values() {
        let config = DnsProxyConfig::default();
        assert_eq!(config.listen_addr.port(), 53);
        assert!(config.block_malicious);
        assert!(config.enable_doh);
        assert_eq!(config.cache_size, 10_000);
    }

    #[test]
    fn test_cache_eviction() {
        let mut config = DnsProxyConfig::default();
        config.cache_size = 3;
        let mut proxy = DnsProxy::with_config(config);

        for i in 0..5 {
            let answer = DnsAnswer {
                name: format!("host{i}.example"),
                rdata: format!("10.0.0.{i}"),
                ttl: 300,
                record_type: DnsRecordType::A,
            };
            proxy.cache_insert(format!("host{i}.example"), answer);
        }

        assert_eq!(proxy.cache.len(), 3);
        assert!(proxy.cache_lookup("host0.example").is_none());
        assert!(proxy.cache_lookup("host4.example").is_some());
    }
}
