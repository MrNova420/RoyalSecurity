#[cfg(test)]
mod tests {
    use crate::stix::*;
    use crate::converters::*;
    use crate::taxii::*;
    use royalsecurity_threat_intel::feed::{IocEntry, IocType};
    use royalsecurity_common::types::{ThreatInfo, EventSeverity, ThreatStatus};
    use chrono::Utc;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_ioc(ioc_type: IocType, value: &str) -> IocEntry {
        IocEntry {
            value: value.to_string(),
            ioc_type,
            confidence: 0.85,
            severity: "high".to_string(),
            source: "test-feed".to_string(),
            tags: vec!["malware".to_string(), "apt28".to_string()],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            expiry: None,
        }
    }

    fn test_threat() -> ThreatInfo {
        ThreatInfo {
            id: uuid::Uuid::new_v4(),
            name: "APT28 X-Agent".to_string(),
            description: "Russian state-sponsored APT".to_string(),
            severity: EventSeverity::Critical,
            mitre_tactic: Some("Initial Access".to_string()),
            mitre_technique: Some("T1566".to_string()),
            iocs: vec![
                "evil-apt28.ru".to_string(),
                "192.168.100.1".to_string(),
            ],
            affected_hosts: vec!["dc01.corp.local".to_string()],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            status: ThreatStatus::Active,
        }
    }

    #[test]
    fn test_ioc_to_stix_indicator_ip() {
        let ioc = test_ioc(IocType::IpAddress, "10.0.0.1");
        let obj = ioc_to_stix(&ioc);
        match obj {
            StixObject::Indicator(ind) => {
                assert!(ind.pattern.contains("ipv4-addr:value"));
                assert!(ind.pattern.contains("10.0.0.1"));
                assert_eq!(ind.pattern_type, "stix");
                assert_eq!(ind.confidence, Some(85));
            }
            _ => panic!("Expected Indicator"),
        }
    }

    #[test]
    fn test_ioc_to_stix_indicator_domain() {
        let ioc = test_ioc(IocType::Domain, "evil.com");
        let obj = ioc_to_stix(&ioc);
        match obj {
            StixObject::Indicator(ind) => {
                assert!(ind.pattern.contains("domain-name:value"));
                assert!(ind.pattern.contains("evil.com"));
            }
            _ => panic!("Expected Indicator"),
        }
    }

    #[test]
    fn test_ioc_to_stix_indicator_sha256() {
        let hash = "a".repeat(64);
        let ioc = test_ioc(IocType::FileHashSha256, &hash);
        let obj = ioc_to_stix(&ioc);
        match obj {
            StixObject::Indicator(ind) => {
                assert!(ind.pattern.contains("SHA-256"));
                assert_eq!(ind.labels, vec!["malware", "apt28"]);
            }
            _ => panic!("Expected Indicator"),
        }
    }

    #[test]
    fn test_ioc_to_stix_indicator_url() {
        let ioc = test_ioc(IocType::Url, "http://evil.com/payload.exe");
        let obj = ioc_to_stix(&ioc);
        match obj {
            StixObject::Indicator(ind) => {
                assert!(ind.pattern.contains("url:value"));
                assert!(ind.pattern.contains("http://evil.com/payload.exe"));
            }
            _ => panic!("Expected Indicator"),
        }
    }

    #[test]
    fn test_bundle_creation() {
        let mut bundle = StixBundle::new();
        assert_eq!(bundle.bundle_type, "bundle");
        assert!(bundle.id.starts_with("bundle--"));
        assert_eq!(bundle.spec_version, "2.1");
        assert!(bundle.objects.is_empty());

        let ioc1 = test_ioc(IocType::Domain, "bad.com");
        let ioc2 = test_ioc(IocType::IpAddress, "1.2.3.4");
        bundle.add_object(ioc_to_stix(&ioc1));
        bundle.add_object(ioc_to_stix(&ioc2));
        assert_eq!(bundle.objects.len(), 2);
    }

    #[test]
    fn test_bundle_to_json() {
        let ioc = test_ioc(IocType::Domain, "test.com");
        let bundle = StixBundle::with_objects(vec![ioc_to_stix(&ioc)]);
        let json = bundle.to_json().unwrap();
        assert!(json.contains("bundle"));
        assert!(json.contains("indicator"));
        assert!(json.contains("test.com"));
        assert!(json.contains("2.1"));
    }

    #[test]
    fn test_threat_to_stix_conversion() {
        let threat = test_threat();
        let objects = threat_to_stix(&threat);
        assert!(!objects.is_empty());
        let has_malware = objects.iter().any(|o| matches!(o, StixObject::Malware(_)));
        assert!(has_malware, "Should contain Malware object");
        let has_attack_pattern = objects.iter().any(|o| matches!(o, StixObject::AttackPattern(_)));
        assert!(has_attack_pattern, "Should contain AttackPattern for T1566");
        let has_relationship = objects.iter().any(|o| matches!(o, StixObject::Relationship(_)));
        assert!(has_relationship, "Should contain Relationship linking malware to attack pattern");
    }

    #[test]
    fn test_yara_rule_to_stix_conversion() {
        let objects = yara_rule_to_stix(
            "APT28_Dropper",
            "rule APT28_Dropper { strings: $s1 = \"evil\" condition: $s1 }",
            Some("Detects APT28 dropper"),
        );
        assert!(objects.len() >= 2);
        let has_malware = objects.iter().any(|o| matches!(o, StixObject::Malware(_)));
        assert!(has_malware);
        let has_indicator = objects.iter().any(|o| matches!(o, StixObject::Indicator(_)));
        assert!(has_indicator);
        match objects.iter().find(|o| matches!(o, StixObject::Indicator(_))).unwrap() {
            StixObject::Indicator(ind) => {
                assert_eq!(ind.pattern_type, "yara");
                assert!(ind.pattern.contains("rule APT28_Dropper"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_sigma_rule_to_stix_conversion() {
        let objects = sigma_rule_to_stix(
            "Suspicious_Powershell",
            Some("Detects suspicious PowerShell execution"),
            Some("T1059.001"),
        );
        assert!(!objects.is_empty());
        let has_attack_pattern = objects.iter().any(|o| matches!(o, StixObject::AttackPattern(_)));
        assert!(has_attack_pattern);
        let has_indicator = objects.iter().any(|o| matches!(o, StixObject::Indicator(_)));
        assert!(has_indicator);
        match objects.iter().find(|o| matches!(o, StixObject::Indicator(_))).unwrap() {
            StixObject::Indicator(ind) => {
                assert_eq!(ind.pattern_type, "sigma");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_mitre_to_stix_conversion() {
        let objects = mitre_to_stix(
            "T1566",
            "Phishing",
            Some("Adversaries send phishing emails"),
            Some("Initial Access"),
        );
        assert_eq!(objects.len(), 1);
        match &objects[0] {
            StixObject::AttackPattern(ap) => {
                assert_eq!(ap.name, "Phishing");
                let refs = ap.external_references.as_ref().unwrap();
                assert_eq!(refs[0].external_id, Some("T1566".to_string()));
                assert!(refs[0].url.as_ref().unwrap().contains("T1566"));
                let kc = ap.kill_chain_phases.as_ref().unwrap();
                assert_eq!(kc[0].phase_name, "initial-access");
            }
            _ => panic!("Expected AttackPattern"),
        }
    }

    fn create_test_state() -> TaxiiState {
        let mut collections_map = std::collections::HashMap::new();
        collections_map.insert(
            "col-test-001".to_string(),
            TaxiiCollection {
                id: "col-test-001".to_string(),
                title: "Test Collection".to_string(),
                description: Some("Test collection for unit tests".to_string()),
                can_read: true,
                can_write: true,
                media_types: vec!["application/stix+json;version=2.1".to_string()],
            },
        );

        let mut objects_map = std::collections::HashMap::new();
        objects_map.insert(
            "col-test-001".to_string(),
            vec![],
        );

        TaxiiState {
            collections: std::sync::Arc::new(std::sync::RwLock::new(collections_map)),
            objects: std::sync::Arc::new(std::sync::RwLock::new(objects_map)),
            manifests: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    #[test]
    fn test_taxii_discovery_endpoint() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = create_test_state();
            let app = create_router(state);
            let resp = app.oneshot(Request::builder().uri("/taxii2/").body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_taxii_list_collections() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = create_test_state();
            let app = create_router(state);
            let resp = app.oneshot(Request::builder().uri("/taxii2/collections/").body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_taxii_get_objects_empty_collection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = create_test_state();
            let app = create_router(state);
            let resp = app.oneshot(Request::builder().uri("/taxii2/collections/col-test-001/objects/?limit=10").body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }

    #[test]
    fn test_taxii_get_nonexistent_collection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = create_test_state();
            let app = create_router(state);
            let resp = app.oneshot(Request::builder().uri("/taxii2/collections/nonexistent").body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn test_taxii_add_objects() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let state = create_test_state();
            let app = create_router(state.clone());
            let body = serde_json::json!({
                "objects": [{
                    "type": "indicator",
                    "id": "indicator--test-001",
                    "spec_version": "2.1",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "name": "Test",
                    "pattern": "[domain-name:value = 'test.com']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "labels": ["test"]
                }]
            });
            let resp = app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/taxii2/collections/col-test-001/objects/")
                    .header("content-type", "application/taxii+json;version=2.1")
                    .body(Body::from(body.to_string()))
                    .unwrap()
            ).await.unwrap();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);

            let objects = state.objects.read().unwrap();
            let col_objects = objects.get("col-test-001").unwrap();
            assert_eq!(col_objects.len(), 1);
        });
    }
}
