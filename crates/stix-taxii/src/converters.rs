use crate::stix::*;
use royalsecurity_threat_intel::feed::{IocEntry, IocType};
use royalsecurity_common::types::ThreatInfo;
use chrono::Utc;
use uuid::Uuid;

fn stix_id(prefix: &str) -> String {
    format!("{}--{}", prefix, Uuid::new_v4())
}

pub fn ioc_to_stix(ioc: &IocEntry) -> StixObject {
    let pattern = match ioc.ioc_type {
        IocType::IpAddress => format!("[ipv4-addr:value = '{}']", ioc.value),
        IocType::Cidr => format!("[ipv4-addr:value = '{}']", ioc.value),
        IocType::Domain => format!("[domain-name:value = '{}']", ioc.value),
        IocType::Url => format!("[url:value = '{}']", ioc.value),
        IocType::FileHashSha256 => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
        IocType::FileHashSha1 => format!("[file:hashes.'SHA-1' = '{}']", ioc.value),
        IocType::FileHashMd5 => format!("[file:hashes.MD5 = '{}']", ioc.value),
        IocType::FilePath => format!("[file:path = '{}']", ioc.value),
        IocType::EmailAddress => format!("[email-addr:value = '{}']", ioc.value),
        IocType::Mutex => format!("[mutex:name = '{}']", ioc.value),
        IocType::RegistryKey => format!("[file:path = '{}']", ioc.value),
        IocType::CertificateThumbprint => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
        IocType::YaraRule => format!("[artifact:payload_bin = '{}']", ioc.value),
    };

    StixObject::Indicator(Indicator {
        common: CommonFields {
            id: stix_id("indicator"),
            spec_version: "2.1".to_string(),
            created: ioc.first_seen,
            modified: ioc.last_seen,
        },
        name: Some(format!("{}: {}", ioc_type_label(&ioc.ioc_type), ioc.value)),
        description: Some(format!("IOC from source: {}", ioc.source)),
        pattern,
        pattern_type: "stix".to_string(),
        valid_from: ioc.first_seen,
        valid_until: ioc.expiry,
        labels: ioc.tags.clone(),
        confidence: Some((ioc.confidence * 100.0) as u8),
        kill_chain_phases: None,
    })
}

pub fn threat_to_stix_objects(threat: &ThreatInfo) -> Vec<StixObject> {
    let mut objects = Vec::new();

    let malware_id = stix_id("malware");
    objects.push(StixObject::Malware(Malware {
        common: CommonFields {
            id: malware_id.clone(),
            spec_version: "2.1".to_string(),
            created: threat.first_seen,
            modified: threat.last_seen,
        },
        name: threat.name.clone(),
        description: Some(threat.description.clone()),
        malware_types: vec!["malicious-activity".to_string()],
        first_seen: Some(threat.first_seen),
        last_seen: Some(threat.last_seen),
        kill_chain_phases: threat.mitre_tactic.as_ref().map(|tactic| {
            vec![KillChainPhase {
                kill_chain_name: "lockheed-martin-cyber-kill-chain".to_string(),
                phase_name: tactic.to_lowercase().replace(' ', "-"),
            }]
        }),
        is_family: false,
    }));

    if let Some(ref technique_id) = threat.mitre_technique {
        let ap_id = stix_id("attack-pattern");
        objects.push(StixObject::AttackPattern(AttackPattern {
            common: CommonFields {
                id: ap_id.clone(),
                spec_version: "2.1".to_string(),
                created: threat.first_seen,
                modified: threat.last_seen,
            },
            name: technique_id.clone(),
            description: Some(format!("MITRE ATT&CK technique: {}", technique_id)),
            kill_chain_phases: None,
            external_references: Some(vec![ExternalReference {
                source_name: "mitre-attack".to_string(),
                url: Some(format!("https://attack.mitre.org/techniques/{}/", technique_id)),
                external_id: Some(technique_id.clone()),
            }]),
        }));

        objects.push(StixObject::Relationship(Relationship {
            common: CommonFields {
                id: stix_id("relationship"),
                spec_version: "2.1".to_string(),
                created: threat.first_seen,
                modified: threat.last_seen,
            },
            relationship_type: "uses".to_string(),
            source_ref: malware_id,
            target_ref: ap_id,
        }));
    }

    for ioc_val in &threat.iocs {
        objects.push(ioc_to_stix(&IocEntry {
            value: ioc_val.clone(),
            ioc_type: IocType::Domain,
            confidence: 0.7,
            severity: threat.severity.to_string().to_lowercase(),
            source: threat.name.clone(),
            tags: vec![],
            first_seen: threat.first_seen,
            last_seen: threat.last_seen,
            expiry: None,
        }));
    }

    objects
}

pub fn yara_rule_to_stix(
    rule_name: &str,
    rule_content: &str,
    description: Option<&str>,
) -> Vec<StixObject> {
    let now = Utc::now();
    let mut objects = Vec::new();

    let malware_id = stix_id("malware");
    objects.push(StixObject::Malware(Malware {
        common: CommonFields {
            id: malware_id.clone(),
            spec_version: "2.1".to_string(),
            created: now,
            modified: now,
        },
        name: rule_name.to_string(),
        description: description.map(|s| s.to_string()),
        malware_types: vec!["backdoor".to_string(), "remote-access-trojan".to_string()],
        first_seen: Some(now),
        last_seen: Some(now),
        kill_chain_phases: Some(vec![
            KillChainPhase {
                kill_chain_name: "lockheed-martin-cyber-kill-chain".to_string(),
                phase_name: "installation".to_string(),
            },
        ]),
        is_family: true,
    }));

    let indicator_id = stix_id("indicator");
    objects.push(StixObject::Indicator(Indicator {
        common: CommonFields {
            id: indicator_id.clone(),
            spec_version: "2.1".to_string(),
            created: now,
            modified: now,
        },
        name: Some(format!("YARA: {}", rule_name)),
        description: description.map(|s| s.to_string()),
        pattern: rule_content.to_string(),
        pattern_type: "yara".to_string(),
        valid_from: now,
        valid_until: None,
        labels: vec!["malware".to_string(), "yara".to_string()],
        confidence: Some(80),
        kill_chain_phases: None,
    }));

    objects.push(StixObject::Relationship(Relationship {
        common: CommonFields {
            id: stix_id("relationship"),
            spec_version: "2.1".to_string(),
            created: now,
            modified: now,
        },
        relationship_type: "indicates".to_string(),
        source_ref: indicator_id,
        target_ref: malware_id,
    }));

    objects
}

pub fn sigma_rule_to_stix(
    rule_name: &str,
    description: Option<&str>,
    mitre_technique: Option<&str>,
) -> Vec<StixObject> {
    let now = Utc::now();
    let mut objects = Vec::new();

    let ap_id = stix_id("attack-pattern");
    objects.push(StixObject::AttackPattern(AttackPattern {
        common: CommonFields {
            id: ap_id.clone(),
            spec_version: "2.1".to_string(),
            created: now,
            modified: now,
        },
        name: rule_name.to_string(),
        description: description.map(|s| s.to_string()),
        kill_chain_phases: mitre_technique.map(|_| {
            vec![KillChainPhase {
                kill_chain_name: "lockheed-martin-cyber-kill-chain".to_string(),
                phase_name: "detection".to_string(),
            }]
        }),
        external_references: mitre_technique.map(|t| {
            vec![ExternalReference {
                source_name: "mitre-attack".to_string(),
                url: Some(format!("https://attack.mitre.org/techniques/{}/", t)),
                external_id: Some(t.to_string()),
            }]
        }),
    }));

    objects.push(StixObject::Indicator(Indicator {
        common: CommonFields {
            id: stix_id("indicator"),
            spec_version: "2.1".to_string(),
            created: now,
            modified: now,
        },
        name: Some(format!("Sigma: {}", rule_name)),
        description: description.map(|s| s.to_string()),
        pattern: format!("sigma:'{}'", rule_name),
        pattern_type: "sigma".to_string(),
        valid_from: now,
        valid_until: None,
        labels: vec!["detection-rule".to_string(), "sigma".to_string()],
        confidence: Some(75),
        kill_chain_phases: None,
    }));

    objects
}

pub fn mitre_to_stix(
    technique_id: &str,
    technique_name: &str,
    description: Option<&str>,
    tactic: Option<&str>,
) -> Vec<StixObject> {
    let now = Utc::now();

    vec![StixObject::AttackPattern(AttackPattern {
        common: CommonFields {
            id: stix_id("attack-pattern"),
            spec_version: "2.1".to_string(),
            created: now,
            modified: now,
        },
        name: technique_name.to_string(),
        description: description.map(|s| s.to_string()),
        kill_chain_phases: tactic.map(|t| {
            vec![KillChainPhase {
                kill_chain_name: "lockheed-martin-cyber-kill-chain".to_string(),
                phase_name: t.to_lowercase().replace(' ', "-"),
            }]
        }),
        external_references: Some(vec![ExternalReference {
            source_name: "mitre-attack".to_string(),
            url: Some(format!("https://attack.mitre.org/techniques/{}/", technique_id)),
            external_id: Some(technique_id.to_string()),
        }]),
    })]
}

fn ioc_type_label(ioc_type: &IocType) -> &str {
    match ioc_type {
        IocType::IpAddress => "IPv4 Address",
        IocType::Domain => "Domain",
        IocType::Url => "URL",
        IocType::FileHashSha256 => "SHA-256",
        IocType::FileHashSha1 => "SHA-1",
        IocType::FileHashMd5 => "MD5",
        IocType::FilePath => "File Path",
        IocType::EmailAddress => "Email",
        IocType::Mutex => "Mutex",
        IocType::RegistryKey => "Registry Key",
        IocType::CertificateThumbprint => "Certificate",
        IocType::Cidr => "CIDR",
        IocType::YaraRule => "YARA",
    }
}
