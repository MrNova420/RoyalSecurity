pub mod feed;
pub mod feeds;
pub mod matcher;
pub mod stix;
pub mod updater;

pub use royalsecurity_core as core;
pub use royalsecurity_common as common;
pub use feed::*;
pub use feeds::*;
pub use matcher::*;
pub use stix::*;
pub use updater::{RuleUpdater, UpdateFeed, UpdateResult};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::{FeedManager, IocType, IocEntry};
    use crate::matcher::IocMatcher;
    use chrono::Utc;

    #[test]
    fn test_ioc_type_classification() {
        assert_eq!(IocType::from_string("ip"), IocType::IpAddress);
        assert_eq!(IocType::from_string("domain"), IocType::Domain);
        assert_eq!(IocType::from_string("sha256"), IocType::FileHashSha256);
        assert_eq!(IocType::from_string("url"), IocType::Url);
    }

    #[test]
    fn test_feed_manager_parse_line_delimited() {
        let text = "# Comment\n8.8.8.8\nmalware.evil.com\nhttp://bad.com/payload\n";
        let entries = FeedManager::parse_line_delimited(text, "test-feed");
        assert_eq!(entries.len(), 3, "Should parse 3 IOCs from line-delimited text");
    }

    #[test]
    fn test_feed_manager_classify_ip() {
        let ioc = FeedManager::classify_ioc("192.168.1.1", "test");
        assert!(ioc.is_some());
        assert_eq!(ioc.unwrap().ioc_type, IocType::IpAddress);
    }

    #[test]
    fn test_feed_manager_classify_hash() {
        let sha256 = "a".repeat(64);
        let ioc = FeedManager::classify_ioc(&sha256, "test");
        assert!(ioc.is_some());
        assert_eq!(ioc.unwrap().ioc_type, IocType::FileHashSha256);
    }

    #[test]
    fn test_feed_manager_classify_domain() {
        let ioc = FeedManager::classify_ioc("evil.com", "test");
        assert!(ioc.is_some());
        assert_eq!(ioc.unwrap().ioc_type, IocType::Domain);
    }

    #[test]
    fn test_feed_manager_skip_comments_and_empty() {
        let text = "# This is a comment\n\n# Another comment\n";
        let entries = FeedManager::parse_line_delimited(text, "test");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_ioc_matcher_load_and_check() {
        let mut matcher = IocMatcher::new();
        
        let iocs = vec![
            IocEntry {
                value: "evil.com".into(),
                ioc_type: IocType::Domain,
                confidence: 0.9,
                severity: "high".into(),
                source: "test".into(),
                tags: vec!["malware".into()],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                expiry: None,
            },
            IocEntry {
                value: "1.2.3.4".into(),
                ioc_type: IocType::IpAddress,
                confidence: 0.8,
                severity: "medium".into(),
                source: "test".into(),
                tags: vec![],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                expiry: None,
            },
        ];
        
        matcher.load_iocs(iocs);
        assert_eq!(matcher.ioc_count(), 2);
        
        let found = matcher.check_value("evil.com");
        assert!(found.is_some());
        assert_eq!(found.unwrap().ioc_type, IocType::Domain);
        
        let not_found = matcher.check_value("safe.com");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_ioc_matcher_batch_check() {
        let mut matcher = IocMatcher::new();
        let iocs = vec![
            IocEntry {
                value: "bad.com".into(),
                ioc_type: IocType::Domain,
                confidence: 0.9,
                severity: "high".into(),
                source: "test".into(),
                tags: vec![],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                expiry: None,
            },
        ];
        matcher.load_iocs(iocs);
        
        let values = vec!["bad.com", "good.com", "another.com"];
        let results = matcher.check_batch(&values);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "bad.com");
    }

    #[test]
    fn test_stix_bundle_parse() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--12345",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--12345",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "name": "Test IOC",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z"
                }
            ]
        }"#;
        
        let bundle = stix::StixBundle::parse(json).unwrap();
        assert_eq!(bundle.objects.len(), 1);
        
        let indicators = bundle.indicators();
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].name, Some("Test IOC".into()));
    }
}
