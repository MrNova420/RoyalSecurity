pub mod prelude;

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TrackerType {
    Analytics,
    Advertising,
    Social,
    Fingerprinting,
    Cryptominer,
    Malware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerEntry {
    pub domain: String,
    pub tracker_type: TrackerType,
    pub category: String,
    pub first_seen: DateTime<Utc>,
    pub blocked_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub domain: String,
    pub path: String,
    pub is_third_party: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResult {
    pub blocked: bool,
    pub tracker_entry: Option<TrackerEntry>,
    pub reason: String,
}

pub struct TrackerBlocker {
    trackers: HashMap<String, TrackerEntry>,
    total_blocked: u32,
}

impl TrackerBlocker {
    pub fn new() -> Self {
        let mut tracker_list: HashMap<String, TrackerEntry> = HashMap::new();

        let defaults: Vec<(&str, TrackerType, &str)> = vec![
            ("google-analytics.com", TrackerType::Analytics, "Web Analytics"),
            ("googletagmanager.com", TrackerType::Analytics, "Tag Management"),
            ("facebook.net", TrackerType::Social, "Social Widget"),
            ("connect.facebook.net", TrackerType::Social, "Social Tracking"),
            ("doubleclick.net", TrackerType::Advertising, "Ad Network"),
            ("googlesyndication.com", TrackerType::Advertising, "Ad Serving"),
            ("ads.yahoo.com", TrackerType::Advertising, "Ad Network"),
            ("cryptojacking.com", TrackerType::Cryptominer, "Crypto Mining"),
            ("coinhive.com", TrackerType::Cryptominer, "Crypto Mining"),
            ("fingerprint.com", TrackerType::Fingerprinting, "Browser Fingerprinting"),
            ("hotjar.com", TrackerType::Analytics, "Heatmap Analytics"),
            ("mixpanel.com", TrackerType::Analytics, "Product Analytics"),
            ("amplitude.com", TrackerType::Analytics, "Product Analytics"),
            ("segment.com", TrackerType::Analytics, "Customer Data"),
            ("sentry.io", TrackerType::Analytics, "Error Tracking"),
        ];

        for (domain, tracker_type, category) in defaults {
            tracker_list.insert(
                domain.to_string(),
                TrackerEntry {
                    domain: domain.to_string(),
                    tracker_type,
                    category: category.to_string(),
                    first_seen: Utc::now(),
                    blocked_count: 0,
                },
            );
        }

        Self {
            trackers: tracker_list,
            total_blocked: 0,
        }
    }

    pub fn should_block(&mut self, request: &BlockRequest) -> BlockResult {
        let domain = &request.domain;

        if let Some(entry) = self.trackers.get_mut(domain) {
            entry.blocked_count += 1;
            self.total_blocked += 1;

            return BlockResult {
                blocked: true,
                tracker_entry: Some(entry.clone()),
                reason: format!(
                    "Domain '{}' matched tracker type {:?} ({})",
                    domain, entry.tracker_type, entry.category
                ),
            };
        }

        if request.is_third_party {
            for (tracker_domain, entry) in &mut self.trackers {
                if domain.ends_with(tracker_domain) || domain.contains(tracker_domain) {
                    entry.blocked_count += 1;
                    self.total_blocked += 1;

                    return BlockResult {
                        blocked: true,
                        tracker_entry: Some(entry.clone()),
                        reason: format!(
                            "Third-party domain '{}' matches known tracker '{}'",
                            domain, tracker_domain
                        ),
                    };
                }
            }
        }

        BlockResult {
            blocked: false,
            tracker_entry: None,
            reason: "No tracker match found".to_string(),
        }
    }

    pub fn add_tracker(&mut self, domain: &str, tracker_type: TrackerType, category: &str) {
        self.trackers.insert(
            domain.to_string(),
            TrackerEntry {
                domain: domain.to_string(),
                tracker_type,
                category: category.to_string(),
                first_seen: Utc::now(),
                blocked_count: 0,
            },
        );
    }

    pub fn remove_tracker(&mut self, domain: &str) -> bool {
        self.trackers.remove(domain).is_some()
    }

    pub fn is_tracker(&self, domain: &str) -> bool {
        self.trackers.contains_key(domain)
    }

    pub fn tracker_stats(&self) -> HashMap<TrackerType, u32> {
        let mut stats: HashMap<TrackerType, u32> = HashMap::new();
        for entry in self.trackers.values() {
            *stats.entry(entry.tracker_type.clone()).or_insert(0) += entry.blocked_count;
        }
        stats
    }

    pub fn blocked_count(&self) -> u32 {
        self.total_blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker_blocker() {
        let blocker = TrackerBlocker::new();
        assert!(blocker.blocked_count() == 0);
        assert!(blocker.is_tracker("google-analytics.com"));
    }

    #[test]
    fn test_block_known_tracker() {
        let mut blocker = TrackerBlocker::new();
        let request = BlockRequest {
            domain: "google-analytics.com".to_string(),
            path: "/collect".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(result.blocked);
        assert!(result.tracker_entry.is_some());
        assert_eq!(result.tracker_entry.unwrap().tracker_type, TrackerType::Analytics);
    }

    #[test]
    fn test_allow_clean_domain() {
        let mut blocker = TrackerBlocker::new();
        let request = BlockRequest {
            domain: "github.com".to_string(),
            path: "/user/repo".to_string(),
            is_third_party: false,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(!result.blocked);
        assert!(result.tracker_entry.is_none());
    }

    #[test]
    fn test_add_custom_tracker() {
        let mut blocker = TrackerBlocker::new();
        blocker.add_tracker("custom-tracker.io", TrackerType::Advertising, "Custom Ad");

        assert!(blocker.is_tracker("custom-tracker.io"));

        let request = BlockRequest {
            domain: "custom-tracker.io".to_string(),
            path: "/ad".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(result.blocked);
    }

    #[test]
    fn test_remove_tracker() {
        let mut blocker = TrackerBlocker::new();
        assert!(blocker.is_tracker("facebook.net"));
        assert!(blocker.remove_tracker("facebook.net"));
        assert!(!blocker.is_tracker("facebook.net"));
        assert!(!blocker.remove_tracker("facebook.net"));
    }

    #[test]
    fn test_third_party_subdomain_match() {
        let mut blocker = TrackerBlocker::new();
        let request = BlockRequest {
            domain: "ads.doubleclick.net".to_string(),
            path: "/track".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(result.blocked);
    }

    #[test]
    fn test_tracker_stats() {
        let mut blocker = TrackerBlocker::new();
        let request1 = BlockRequest {
            domain: "google-analytics.com".to_string(),
            path: "/".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };
        let request2 = BlockRequest {
            domain: "doubleclick.net".to_string(),
            path: "/".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        blocker.should_block(&request1);
        blocker.should_block(&request2);

        let stats = blocker.tracker_stats();
        assert_eq!(stats.get(&TrackerType::Analytics), Some(&1));
        assert_eq!(stats.get(&TrackerType::Advertising), Some(&1));
    }

    #[test]
    fn test_blocked_count_accumulates() {
        let mut blocker = TrackerBlocker::new();
        let request = BlockRequest {
            domain: "hotjar.com".to_string(),
            path: "/track".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        blocker.should_block(&request);
        blocker.should_block(&request);
        blocker.should_block(&request);

        assert_eq!(blocker.blocked_count(), 3);
    }

    #[test]
    fn test_add_and_remove_malware_tracker() {
        let mut blocker = TrackerBlocker::new();
        blocker.add_tracker("evil.miner", TrackerType::Cryptominer, "Browser Mining");
        assert!(blocker.is_tracker("evil.miner"));

        let request = BlockRequest {
            domain: "evil.miner".to_string(),
            path: "/mine".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(result.blocked);
        assert_eq!(result.tracker_entry.unwrap().tracker_type, TrackerType::Cryptominer);

        blocker.remove_tracker("evil.miner");
        assert!(!blocker.is_tracker("evil.miner"));
    }

    #[test]
    fn test_social_tracker_detection() {
        let mut blocker = TrackerBlocker::new();
        let request = BlockRequest {
            domain: "facebook.net".to_string(),
            path: "/plugins/like".to_string(),
            is_third_party: true,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(result.blocked);
        assert_eq!(result.tracker_entry.unwrap().tracker_type, TrackerType::Social);
    }

    #[test]
    fn test_non_third_party_not_subdomain() {
        let mut blocker = TrackerBlocker::new();
        let request = BlockRequest {
            domain: "some-other-site.com".to_string(),
            path: "/page".to_string(),
            is_third_party: false,
            timestamp: Utc::now(),
        };

        let result = blocker.should_block(&request);
        assert!(!result.blocked);
    }
}
