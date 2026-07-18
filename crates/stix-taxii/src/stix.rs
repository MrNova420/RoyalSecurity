use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use royalsecurity_common::types::ThreatInfo;
use royalsecurity_threat_intel::feed::{IocEntry, IocType};

const STIX_SPEC_VERSION: &str = "2.1";

fn stix_id(prefix: &str) -> String {
    format!("{}--{}", prefix, Uuid::new_v4())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    pub spec_version: String,
    pub objects: Vec<StixObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StixObject {
    #[serde(rename = "indicator")]
    Indicator(Indicator),
    #[serde(rename = "malware")]
    Malware(Malware),
    #[serde(rename = "threat-actor")]
    ThreatActor(ThreatActor),
    #[serde(rename = "campaign")]
    Campaign(Campaign),
    #[serde(rename = "attack-pattern")]
    AttackPattern(AttackPattern),
    #[serde(rename = "report")]
    Report(Report),
    #[serde(rename = "relationship")]
    Relationship(Relationship),
    #[serde(rename = "observed-data")]
    ObservedData(ObservedData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonFields {
    pub id: String,
    #[serde(rename = "spec_version")]
    pub spec_version: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    #[serde(flatten)]
    pub common: CommonFields,
    pub name: Option<String>,
    pub description: Option<String>,
    pub pattern: String,
    #[serde(rename = "pattern_type")]
    pub pattern_type: String,
    #[serde(rename = "valid_from")]
    pub valid_from: DateTime<Utc>,
    #[serde(rename = "valid_until", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub labels: Vec<String>,
    pub confidence: Option<u8>,
    #[serde(rename = "kill_chain_phases", skip_serializing_if = "Option::is_none")]
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Malware {
    #[serde(flatten)]
    pub common: CommonFields,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "malware_types")]
    pub malware_types: Vec<String>,
    #[serde(rename = "first_seen", skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(rename = "last_seen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(rename = "kill_chain_phases", skip_serializing_if = "Option::is_none")]
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    pub is_family: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    #[serde(flatten)]
    pub common: CommonFields,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "threat_actor_types")]
    pub threat_actor_types: Vec<String>,
    pub sophistication: Option<String>,
    #[serde(rename = "resource_level")]
    pub resource_level: Option<String>,
    #[serde(rename = "primary_motivation")]
    pub primary_motivation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    #[serde(flatten)]
    pub common: CommonFields,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "first_seen", skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(rename = "last_seen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    pub objective: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    #[serde(flatten)]
    pub common: CommonFields,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "kill_chain_phases", skip_serializing_if = "Option::is_none")]
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    #[serde(rename = "external_references", skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    #[serde(flatten)]
    pub common: CommonFields,
    pub name: String,
    pub description: Option<String>,
    pub published: DateTime<Utc>,
    #[serde(rename = "object_refs")]
    pub object_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    #[serde(flatten)]
    pub common: CommonFields,
    #[serde(rename = "relationship_type")]
    pub relationship_type: String,
    #[serde(rename = "source_ref")]
    pub source_ref: String,
    #[serde(rename = "target_ref")]
    pub target_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedData {
    #[serde(flatten)]
    pub common: CommonFields,
    pub objects: Vec<CyberObservable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberObservable {
    #[serde(rename = "type")]
    pub observable_type: String,
    #[serde(flatten)]
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    #[serde(rename = "kill_chain_name")]
    pub kill_chain_name: String,
    #[serde(rename = "phase_name")]
    pub phase_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,
    pub url: Option<String>,
    pub external_id: Option<String>,
}

impl StixBundle {
    pub fn new() -> Self {
        Self {
            bundle_type: "bundle".to_string(),
            id: stix_id("bundle"),
            spec_version: STIX_SPEC_VERSION.to_string(),
            objects: Vec::new(),
        }
    }

    pub fn with_objects(objects: Vec<StixObject>) -> Self {
        Self {
            bundle_type: "bundle".to_string(),
            id: stix_id("bundle"),
            spec_version: STIX_SPEC_VERSION.to_string(),
            objects,
        }
    }

    pub fn add_object(&mut self, obj: StixObject) {
        self.objects.push(obj);
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn indicators(&self) -> Vec<&Indicator> {
        self.objects.iter().filter_map(|o| match o {
            StixObject::Indicator(i) => Some(i),
            _ => None,
        }).collect()
    }

    pub fn malware_objects(&self) -> Vec<&Malware> {
        self.objects.iter().filter_map(|o| match o {
            StixObject::Malware(m) => Some(m),
            _ => None,
        }).collect()
    }
}

pub fn ioc_to_stix_indicator(ioc: &IocEntry) -> Indicator {
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
        IocType::RegistryKey => format!("[win-registry-key:key = '{}']", ioc.value),
        IocType::CertificateThumbprint => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
        IocType::YaraRule => format!("[artifact:payload_bin = '{}']", ioc.value),
    };

    let pattern_type_str = match ioc.ioc_type {
        IocType::YaraRule => "yara",
        _ => "stix",
    };

    Indicator {
        common: CommonFields {
            id: stix_id("indicator"),
            spec_version: STIX_SPEC_VERSION.to_string(),
            created: ioc.first_seen,
            modified: ioc.last_seen,
        },
        name: Some(format!("{}: {}", ioc.ioc_type.ioc_type_str(), ioc.value)),
        description: Some(format!("IOC from source: {}", ioc.source)),
        pattern,
        pattern_type: pattern_type_str.to_string(),
        valid_from: ioc.first_seen,
        valid_until: ioc.expiry,
        labels: ioc.tags.clone(),
        confidence: Some((ioc.confidence * 100.0) as u8),
        kill_chain_phases: None,
    }
}

pub fn threat_to_stix(threat: &ThreatInfo) -> Vec<StixObject> {
    let mut objects = Vec::new();

    let malware_id = stix_id("malware");
    let malware = Malware {
        common: CommonFields {
            id: malware_id.clone(),
            spec_version: STIX_SPEC_VERSION.to_string(),
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
    };
    objects.push(StixObject::Malware(malware));

    if let Some(technique_id) = &threat.mitre_technique {
        let attack_pattern_id = stix_id("attack-pattern");
        let attack_pattern = AttackPattern {
            common: CommonFields {
                id: attack_pattern_id.clone(),
                spec_version: STIX_SPEC_VERSION.to_string(),
                created: threat.first_seen,
                modified: threat.last_seen,
            },
            name: technique_id.clone(),
            description: Some(format!("MITRE technique: {}", technique_id)),
            kill_chain_phases: threat.mitre_tactic.as_ref().map(|tactic| {
                vec![KillChainPhase {
                    kill_chain_name: "lockheed-martin-cyber-kill-chain".to_string(),
                    phase_name: tactic.to_lowercase().replace(' ', "-"),
                }]
            }),
            external_references: Some(vec![ExternalReference {
                source_name: "mitre-attack".to_string(),
                url: Some(format!("https://attack.mitre.org/techniques/{}/", technique_id)),
                external_id: Some(technique_id.clone()),
            }]),
        };
        objects.push(StixObject::AttackPattern(attack_pattern));

        let rel_id = stix_id("relationship");
        objects.push(StixObject::Relationship(Relationship {
            common: CommonFields {
                id: rel_id,
                spec_version: STIX_SPEC_VERSION.to_string(),
                created: threat.first_seen,
                modified: threat.last_seen,
            },
            relationship_type: "uses".to_string(),
            source_ref: malware_id,
            target_ref: attack_pattern_id,
        }));
    }

    for ioc_value in &threat.iocs {
        let indicator_id = stix_id("indicator");
        let indicator = Indicator {
            common: CommonFields {
                id: indicator_id.clone(),
                spec_version: STIX_SPEC_VERSION.to_string(),
                created: threat.first_seen,
                modified: threat.last_seen,
            },
            name: Some(format!("IOC: {}", ioc_value)),
            description: None,
            pattern: format!("[artifact:payload_bin = '{}']", ioc_value),
            pattern_type: "stix".to_string(),
            valid_from: threat.first_seen,
            valid_until: None,
            labels: vec![threat.severity.to_string().to_lowercase()],
            confidence: None,
            kill_chain_phases: None,
        };
        objects.push(StixObject::Indicator(indicator));
    }

    objects
}

pub fn generate_bundle(objects: Vec<StixObject>) -> StixBundle {
    StixBundle::with_objects(objects)
}

trait IocTypeExt {
    fn ioc_type_str(&self) -> &str;
}

impl IocTypeExt for IocType {
    fn ioc_type_str(&self) -> &str {
        match self {
            IocType::IpAddress => "IPv4 Address",
            IocType::Domain => "Domain",
            IocType::Url => "URL",
            IocType::FileHashSha256 => "SHA-256 Hash",
            IocType::FileHashSha1 => "SHA-1 Hash",
            IocType::FileHashMd5 => "MD5 Hash",
            IocType::FilePath => "File Path",
            IocType::EmailAddress => "Email Address",
            IocType::Mutex => "Mutex",
            IocType::RegistryKey => "Registry Key",
            IocType::CertificateThumbprint => "Certificate Thumbprint",
            IocType::Cidr => "CIDR Block",
            IocType::YaraRule => "YARA Rule",
        }
    }
}
