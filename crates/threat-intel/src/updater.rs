use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tracing::{info, warn};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: Arc<std::sync::Mutex<CircuitBreakerState>>,
    consecutive_failures: Arc<AtomicU32>,
    opened_at: Arc<std::sync::Mutex<Option<Instant>>>,
    open_duration: std::time::Duration,
    max_failures: u32,
}

impl CircuitBreaker {
    pub fn new(max_failures: u32, open_duration_secs: u64) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(CircuitBreakerState::Closed)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            opened_at: Arc::new(std::sync::Mutex::new(None)),
            open_duration: std::time::Duration::from_secs(open_duration_secs),
            max_failures,
        }
    }

    pub fn is_available(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                if let Some(opened) = *self.opened_at.lock().unwrap() {
                    if opened.elapsed() >= self.open_duration {
                        *state = CircuitBreakerState::HalfOpen;
                        return true;
                    }
                }
                false
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        *state = CircuitBreakerState::Closed;
    }

    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if failures >= self.max_failures {
            let mut state = self.state.lock().unwrap();
            *state = CircuitBreakerState::Open;
            *self.opened_at.lock().unwrap() = Some(Instant::now());
            warn!(failures = failures, "Circuit breaker tripped, entering Open state");
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeedType {
    Sigma,
    Yara,
    IoC,
    Misp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFeed {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub checksum: String,
    pub last_updated: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    pub feed_name: String,
    pub success: bool,
    pub new_rules: usize,
    pub updated_rules: usize,
    pub errors: Vec<String>,
}

pub struct RuleUpdater {
    feeds: Vec<UpdateFeed>,
    last_update: Option<DateTime<Utc>>,
    _local_rules_path: String,
    _update_interval_secs: u64,
    circuit_breaker: CircuitBreaker,
    cached_data: Option<Vec<u8>>,
}

fn parse_sigma_rules(text: &str) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let docs = yaml_rust2::YamlLoader::load_from_str(text)?;
    let mut count = 0;
    for doc in docs {
        if doc.as_vec().is_some() || doc.as_hash().is_some() {
            count += 1;
        }
    }
    Ok(count)
}

fn parse_yara_rules(text: &str) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let count = text
        .lines()
        .filter(|line| line.trim_start().starts_with("rule ") && line.contains('{'))
        .count();
    Ok(count)
}

impl RuleUpdater {
    pub fn new(local_path: &str) -> Self {
        Self {
            feeds: Vec::new(),
            last_update: None,
            _local_rules_path: local_path.to_string(),
            _update_interval_secs: 3600,
            circuit_breaker: CircuitBreaker::new(5, 60),
            cached_data: None,
        }
    }

    pub fn add_feed(&mut self, feed: UpdateFeed) {
        info!(name = %feed.name, url = %feed.url, "Added update feed");
        self.feeds.push(feed);
    }

    pub fn check_updates(&self) -> Vec<UpdateFeed> {
        self.feeds
            .iter()
            .filter(|f| {
                if let Some(last) = f.last_updated {
                    if let Some(last_update) = self.last_update {
                        last > last_update
                    } else {
                        true
                    }
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    pub async fn download_feed(
        &self,
        feed: &UpdateFeed,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if !self.circuit_breaker.is_available() {
            warn!(feed = %feed.name, "Circuit breaker open, returning cached data");
            if let Some(ref cached) = self.cached_data {
                return Ok(cached.clone());
            }
            return Err("Circuit breaker open, no cached data available".into());
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("RoyalSecurity-RuleUpdater/0.1")
            .build()?;

        let response = client.get(&feed.url).send().await?;
        let data = response.bytes().await?.to_vec();
        info!(feed = %feed.name, bytes = data.len(), "Downloaded feed");
        Ok(data)
    }

    pub fn apply_update(&mut self, feed: &UpdateFeed, data: &[u8]) -> UpdateResult {
        let mut errors = Vec::new();
        let mut new_rules = 0usize;
        let updated_rules = 0usize;

        let checksum = Self::compute_checksum(data);
        info!(
            feed = %feed.name,
            checksum = %checksum,
            bytes = data.len(),
            "Applying update"
        );

        match feed.feed_type {
            FeedType::Sigma => {
                let text = String::from_utf8_lossy(data);
                match parse_sigma_rules(&text) {
                    Ok(count) => new_rules = count,
                    Err(e) => errors.push(format!("Sigma parse error: {}", e)),
                }
            }
            FeedType::Yara => {
                let text = String::from_utf8_lossy(data);
                match parse_yara_rules(&text) {
                    Ok(count) => new_rules = count,
                    Err(e) => errors.push(format!("YARA parse error: {}", e)),
                }
            }
            FeedType::IoC => {
                let text = String::from_utf8_lossy(data);
                let lines: Vec<&str> = text
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .collect();
                new_rules = lines.len();
            }
            FeedType::Misp => match serde_json::from_slice::<serde_json::Value>(data) {
                Ok(_) => {
                    new_rules = 1;
                }
                Err(e) => errors.push(format!("MISP parse error: {}", e)),
            },
        }

        self.last_update = Some(Utc::now());

        UpdateResult {
            feed_name: feed.name.clone(),
            success: errors.is_empty(),
            new_rules,
            updated_rules,
            errors,
        }
    }

    pub async fn full_update(&mut self) -> Vec<UpdateResult> {
        let feeds_to_update: Vec<UpdateFeed> = self.feeds.clone();
        let mut results = Vec::new();

        for feed in &feeds_to_update {
            match self.download_feed(feed).await {
                Ok(data) => {
                    self.circuit_breaker.record_success();
                    self.cached_data = Some(data.clone());
                    let result = self.apply_update(feed, &data);
                    results.push(result);
                }
                Err(e) => {
                    self.circuit_breaker.record_failure();
                    warn!(feed = %feed.name, error = %e, "Failed to download feed");
                    results.push(UpdateResult {
                        feed_name: feed.name.clone(),
                        success: false,
                        new_rules: 0,
                        updated_rules: 0,
                        errors: vec![format!("Download failed: {}", e)],
                    });
                }
            }
        }

        results
    }

    pub fn get_last_update(&self) -> Option<DateTime<Utc>> {
        self.last_update
    }

    pub fn load_builtin_feeds(&mut self) {
        let builtin = vec![
            UpdateFeed {
                name: "RoyalSecurity Sigma Rules".into(),
                url: "https://raw.githubusercontent.com/royalsecurity/rules/main/sigma/rules.yaml"
                    .into(),
                feed_type: FeedType::Sigma,
                checksum: String::new(),
                last_updated: None,
            },
            UpdateFeed {
                name: "RoyalSecurity YARA Rules".into(),
                url: "https://raw.githubusercontent.com/royalsecurity/rules/main/yara/rules.yar"
                    .into(),
                feed_type: FeedType::Yara,
                checksum: String::new(),
                last_updated: None,
            },
            UpdateFeed {
                name: "Community IOC Feed".into(),
                url:
                    "https://raw.githubusercontent.com/royalsecurity/threat-intel/main/iocs/latest.txt"
                        .into(),
                feed_type: FeedType::IoC,
                checksum: String::new(),
                last_updated: None,
            },
            UpdateFeed {
                name: "MISP Galaxy Feed".into(),
                url:
                    "https://raw.githubusercontent.com/royalsecurity/threat-intel/main/misp/events.json"
                        .into(),
                feed_type: FeedType::Misp,
                checksum: String::new(),
                last_updated: None,
            },
        ];

        for feed in builtin {
            info!(name = %feed.name, "Loaded builtin feed");
            self.feeds.push(feed);
        }
    }

    pub fn compute_checksum(data: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_updater_new() {
        let updater = RuleUpdater::new("/tmp/rules");
        assert!(updater.feeds.is_empty());
        assert!(updater.last_update.is_none());
        assert_eq!(updater._local_rules_path, "/tmp/rules");
        assert_eq!(updater._update_interval_secs, 3600);
    }

    #[test]
    fn test_add_feed() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "test-feed".into(),
            url: "https://example.com/rules".into(),
            feed_type: FeedType::Yara,
            checksum: String::new(),
            last_updated: None,
        };
        updater.add_feed(feed);
        assert_eq!(updater.feeds.len(), 1);
        assert_eq!(updater.feeds[0].name, "test-feed");
    }

    #[test]
    fn test_check_updates_all_pending() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        updater.add_feed(UpdateFeed {
            name: "f1".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Sigma,
            checksum: String::new(),
            last_updated: None,
        });
        let pending = updater.check_updates();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_check_updates_after_update() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        updater.add_feed(UpdateFeed {
            name: "f1".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Sigma,
            checksum: String::new(),
            last_updated: Some(Utc::now()),
        });
        updater.last_update = Some(Utc::now());
        let pending = updater.check_updates();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_check_updates_stale_feed() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        updater.add_feed(UpdateFeed {
            name: "f1".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Sigma,
            checksum: String::new(),
            last_updated: Some(Utc::now()),
        });
        updater.last_update = Some(Utc::now() - chrono::Duration::hours(2));
        let pending = updater.check_updates();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_apply_update_ioc() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "ioc-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::IoC,
            checksum: String::new(),
            last_updated: None,
        };
        let data = b"evil.com\n1.2.3.4\nhttp://malware.com/payload\n";
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 3);
        assert!(updater.last_update.is_some());
    }

    #[test]
    fn test_apply_update_ioc_skips_comments() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "ioc-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::IoC,
            checksum: String::new(),
            last_updated: None,
        };
        let data = b"# This is a comment\n\n# Another comment\n";
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 0);
    }

    #[test]
    fn test_apply_update_misp_valid() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "misp-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Misp,
            checksum: String::new(),
            last_updated: None,
        };
        let data = br#"{"type":"misp","Event":{"info":"test"}}"#;
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 1);
    }

    #[test]
    fn test_apply_update_misp_invalid() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "misp-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Misp,
            checksum: String::new(),
            last_updated: None,
        };
        let data = b"not json at all";
        let result = updater.apply_update(&feed, data);
        assert!(!result.success);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_compute_checksum() {
        let data = b"hello world";
        let checksum = RuleUpdater::compute_checksum(data);
        assert_eq!(checksum.len(), 64);
        let checksum2 = RuleUpdater::compute_checksum(data);
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_compute_checksum_different_data() {
        let checksum1 = RuleUpdater::compute_checksum(b"data1");
        let checksum2 = RuleUpdater::compute_checksum(b"data2");
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_load_builtin_feeds() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        updater.load_builtin_feeds();
        assert_eq!(updater.feeds.len(), 4);
        assert!(updater.feeds.iter().any(|f| f.feed_type == FeedType::Sigma));
        assert!(updater.feeds.iter().any(|f| f.feed_type == FeedType::Yara));
        assert!(updater.feeds.iter().any(|f| f.feed_type == FeedType::IoC));
        assert!(updater.feeds.iter().any(|f| f.feed_type == FeedType::Misp));
    }

    #[test]
    fn test_get_last_update_none() {
        let updater = RuleUpdater::new("/tmp/rules");
        assert!(updater.get_last_update().is_none());
    }

    #[test]
    fn test_apply_update_sigma() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "sigma-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Sigma,
            checksum: String::new(),
            last_updated: None,
        };
        let data = br#"title: Test Rule
detection:
    condition: selection
    EventID: 1
level: high
"#;
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 1);
    }

    #[test]
    fn test_apply_update_yara() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "yara-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Yara,
            checksum: String::new(),
            last_updated: None,
        };
        let data = b"rule test_rule { condition: true }";
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 1);
    }

    #[test]
    fn test_apply_update_yara_multiple() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "yara-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Yara,
            checksum: String::new(),
            last_updated: None,
        };
        let data = b"rule a { condition: true }\nrule b { condition: true }\nrule c { condition: true }";
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 3);
    }

    #[test]
    fn test_apply_update_yara_empty() {
        let mut updater = RuleUpdater::new("/tmp/rules");
        let feed = UpdateFeed {
            name: "yara-feed".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Yara,
            checksum: String::new(),
            last_updated: None,
        };
        let data = b"";
        let result = updater.apply_update(&feed, data);
        assert!(result.success);
        assert_eq!(result.new_rules, 0);
    }

    #[test]
    fn test_checksum_is_deterministic() {
        let data = b"deterministic test data for checksum";
        let c1 = RuleUpdater::compute_checksum(data);
        let c2 = RuleUpdater::compute_checksum(data);
        let c3 = RuleUpdater::compute_checksum(data);
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn test_feed_type_serialization() {
        let feed = UpdateFeed {
            name: "test".into(),
            url: "https://example.com".into(),
            feed_type: FeedType::Yara,
            checksum: "abc123".into(),
            last_updated: None,
        };
        let json = serde_json::to_string(&feed).unwrap();
        assert!(json.contains("Yara"));
        let deserialized: UpdateFeed = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.feed_type, FeedType::Yara);
    }

    #[test]
    fn test_update_result_success() {
        let result = UpdateResult {
            feed_name: "test".into(),
            success: true,
            new_rules: 5,
            updated_rules: 2,
            errors: vec![],
        };
        assert!(result.success);
        assert_eq!(result.new_rules, 5);
        assert_eq!(result.updated_rules, 2);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_update_result_with_errors() {
        let result = UpdateResult {
            feed_name: "test".into(),
            success: false,
            new_rules: 0,
            updated_rules: 0,
            errors: vec!["parse error".into()],
        };
        assert!(!result.success);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_circuit_breaker_closed_by_default() {
        let cb = CircuitBreaker::new(5, 60);
        assert!(cb.is_available());
    }

    #[test]
    fn test_circuit_breaker_trips_after_max_failures() {
        let cb = CircuitBreaker::new(3, 60);
        assert!(cb.is_available());
        cb.record_failure();
        assert!(cb.is_available());
        cb.record_failure();
        assert!(cb.is_available());
        cb.record_failure();
        assert!(!cb.is_available());
    }

    #[test]
    fn test_circuit_breaker_records_success_resets() {
        let cb = CircuitBreaker::new(3, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert!(cb.is_available());
    }

    #[test]
    fn test_circuit_breaker_half_open_on_timeout() {
        let cb = CircuitBreaker::new(2, 1);
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_available());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(cb.is_available());
    }

    #[test]
    fn test_circuit_breaker_record_success_closes() {
        let cb = CircuitBreaker::new(2, 60);
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_available());
        cb.record_success();
        assert!(cb.is_available());
    }
}
